"""Look up a pump.fun coin's history on pumpdata.fun before buying it; pays USDC with --pay.

WARNING: with --pay this signs USDC transfers from the wallet in .env and spends
real funds, $0.005 to $0.01 a call. Without --pay it spends nothing and prints
what each call would cost.

Usage:
    uv run cookbook/pumpfun/read/pumpfun_check_token_pumpdata.py <MINT>          # prices only
    uv run cookbook/pumpfun/read/pumpfun_check_token_pumpdata.py <MINT> --pay
    uv run cookbook/pumpfun/read/pumpfun_check_token_pumpdata.py <MINT> --pay --deployer --similar
    uv run cookbook/pumpfun/read/pumpfun_check_token_pumpdata.py <MINT> --buyers 0 --wallet <ADDR>

pumpdata.fun answers from pump.fun's whole trade history, bonding curve and
PumpSwap, and sells each answer per call over x402: no account and no API key.
The calls used:

    GET  /launch/{mint}        $0.005  the deployer's record, the bundle at creation,
                                       the insiders' share of supply, curve progress,
                                       and how launches that looked the same went
    POST /wallets              $0.01   up to 50 wallets' records since day one
    GET  /deployer/{address}   $0.005  --deployer: the deployer's last 90 days
    GET  /similar/{mint}       $0.005  --similar: the nearest past launches, by mint

The default run, /launch plus /wallets, costs $0.015 a coin. The wallets are the
deployer and the first `--buyers` signers on the coin's bonding curve, read from
your RPC, plus any `--wallet`. A wallet's `class` is a rule, not a judgement:
`bot` trades a coin 20+ times a week or 500+ coins, `winner` took out more than
it put in over 20+ coin-weeks, `supply_seller` took out 1.5x what it put in and
100 SOL or more, `new` has no record before this coin, `none` fits no rule.
This script prints the numbers; what to do with them is your rule, not its.

**How x402 pays here.** An unpaid call answers 402 with an offer: an amount of
USDC, a `payTo` wallet and a `feePayer`. The client builds a v0 transaction of
ComputeBudget limit, ComputeBudget price, an SPL `TransferChecked` from its USDC
account to `payTo`'s, and a memo; sets the fee payer to the offer's `feePayer`;
signs it as the transfer authority only; and retries the call with the
transaction in a `PAYMENT-SIGNATURE` header. The server's facilitator adds the
fee payer's signature and lands it, so the wallet needs USDC in its token
account but no SOL for the call. Nothing reaches the chain unless the server
accepts the payment.

The x402 Python SDK (`x402[svm]`) builds the same transaction but pins
`solana<0.40`, and this repo is on 0.40, which dropped `solana.rpc.api`; the
two cannot be installed together, so the flow is written out here with solders.

Docs: https://pumpdata.fun/llms.txt and https://pumpdata.fun/openapi.json.
"""

import argparse
import asyncio
import base64
import json
import os
import secrets
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

import aiohttp
import base58
from dotenv import load_dotenv
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.null_signer import NullSigner
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction
from spl.token.instructions import get_associated_token_address, transfer_checked
from spl.token.models import TransferCheckedParams

load_dotenv()

RPC_ENDPOINT = os.environ.get("SOLANA_NODE_RPC_ENDPOINT")
PRIVATE_KEY = os.environ.get("SOLANA_PRIVATE_KEY")

DEFAULT_API = "https://pumpdata.fun"
DEFAULT_BUYERS = 20
DEFAULT_MAX_USD = 0.01
MAX_WALLETS = 50

PUMP_PROGRAM = Pubkey.from_string("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
TOKEN_PROGRAM = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
MEMO_PROGRAM = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
USDC_MINT = Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
# USDC is a classic SPL Token mint with 6 decimals. The script pays in USDC on
# mainnet only and refuses any other offer, so both are fixed rather than read.
USDC_DECIMALS = 6
SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

# The facilitator rejects a payment whose compute price is above 5 lamports per
# CU; these match the reference x402 client.
PAYMENT_COMPUTE_UNIT_LIMIT = 20_000
PAYMENT_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 1

# getSignaturesForAddress returns at most 1000 a page, newest first. A coin with
# more history than this has its first buyers out of reach; pass --wallet.
SIGNATURE_PAGE = 1000
MAX_SIGNATURE_PAGES = 5


@dataclass
class Answer:
    """One pumpdata call's outcome.

    `price_usd` is the offer's price, set on a 402 and on a paid answer.
    `receipt` is the settled transfer's signature, set only when this call paid.
    """

    status: int
    price_usd: float | None = None
    data: Any = None
    receipt: str | None = None


class OfferRefusedError(Exception):
    """A 402 offer this script will not pay. Raised before anything is signed."""


def payment_required(header: str | None, body: dict) -> dict:
    """The 402's PaymentRequired: the PAYMENT-REQUIRED header, else the body.

    x402 v2 puts the challenge in the base64 header; the body is
    implementation-defined (pumpdata.fun sends it in both).
    """
    if header:
        try:
            return json.loads(base64.b64decode(header))
        except ValueError:
            pass
    return body if isinstance(body, dict) else {}


def pick_offer(body: dict, max_usd: float) -> dict:
    """Choose the USDC-on-Solana `exact` offer from a 402's PaymentRequired.

    Raises:
        OfferRefusedError: If no offer is USDC on Solana mainnet, if it names no fee
            payer, or if it costs more than `max_usd`. Nothing has been signed.
    """
    for offer in body.get("accepts", []):
        if (
            offer.get("scheme") == "exact"
            and offer.get("network") == SOLANA_MAINNET
            and offer.get("asset") == str(USDC_MINT)
        ):
            break
    else:
        raise OfferRefusedError("402 offers no USDC payment on Solana mainnet")  # noqa: TRY003

    if not offer.get("extra", {}).get("feePayer"):
        raise OfferRefusedError("402 offer names no feePayer")  # noqa: TRY003
    price = int(offer["amount"]) / 10**USDC_DECIMALS
    if price > max_usd:
        raise OfferRefusedError(f"402 asks ${price}, above --max-usd ${max_usd}")  # noqa: TRY003
    return offer


def build_payment_header(
    body: dict, offer: dict, payer: Keypair, blockhash: Hash
) -> str:
    """Sign the offer's USDC transfer and encode it as a PAYMENT-SIGNATURE value.

    The transaction is only partly signed: slot 0 belongs to the offer's
    `feePayer` and stays empty until the facilitator signs it.
    """
    fee_payer = Pubkey.from_string(offer["extra"]["feePayer"])
    if fee_payer == payer.pubkey():
        raise OfferRefusedError("402 offer names this wallet as its own fee payer")  # noqa: TRY003
    pay_to = Pubkey.from_string(offer["payTo"])

    transfer = transfer_checked(
        TransferCheckedParams(
            program_id=TOKEN_PROGRAM,
            source=get_associated_token_address(payer.pubkey(), USDC_MINT),
            mint=USDC_MINT,
            dest=get_associated_token_address(pay_to, USDC_MINT),
            owner=payer.pubkey(),
            amount=int(offer["amount"]),
            decimals=USDC_DECIMALS,
        )
    )
    # A random memo keeps two payments of the same amount distinct transactions.
    memo = offer["extra"].get("memo") or secrets.token_hex(16)
    instructions = [
        set_compute_unit_limit(PAYMENT_COMPUTE_UNIT_LIMIT),
        set_compute_unit_price(PAYMENT_COMPUTE_UNIT_PRICE_MICROLAMPORTS),
        transfer,
        Instruction(MEMO_PROGRAM, memo.encode(), []),
    ]
    message = MessageV0.try_compile(fee_payer, instructions, [], blockhash)
    transaction = VersionedTransaction(message, [NullSigner(fee_payer), payer])

    payload = {
        "x402Version": 2,
        "accepted": offer,
        "payload": {"transaction": base64.b64encode(bytes(transaction)).decode()},
    }
    if body.get("resource"):
        payload["resource"] = body["resource"]
    return base64.b64encode(json.dumps(payload).encode()).decode()


async def rpc(
    session: aiohttp.ClientSession, endpoint: str, method: str, params: list
) -> Any:  # noqa: ANN401
    """Make one JSON-RPC call and return its `result`.

    Raises:
        RuntimeError: If the node answers with an error.
    """
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    async with session.post(endpoint, json=body) as response:
        reply = await response.json(content_type=None)
    if "error" in reply:
        raise RuntimeError(f"{method}: {reply['error']}")  # noqa: TRY003
    return reply["result"]


async def read_body(response: aiohttp.ClientResponse) -> dict:
    """A reply's JSON body, or its first 200 characters when it is not JSON."""
    try:
        return await response.json(content_type=None)
    except (json.JSONDecodeError, aiohttp.ContentTypeError):
        return {"error": (await response.text())[:200]}


async def call_pumpdata(  # noqa: PLR0913
    session: aiohttp.ClientSession,
    api: str,
    method: str,
    path: str,
    body: dict | None,
    *,
    payer: Keypair | None,
    rpc_endpoint: str | None,
    max_usd: float,
) -> Answer:
    """Make one pumpdata call, paying for it once if `payer` is given.

    Without `payer` the 402 is returned as it is, with its price. A paid call
    that comes back 402 again is not paid a second time: the server refused the
    payment and nothing settled. A 503 after paying may or may not have
    settled; it is returned, never retried.
    """
    url = f"{api}{path}"
    async with session.request(method, url, json=body) as response:
        status = response.status
        data = await read_body(response)
        challenge = response.headers.get("PAYMENT-REQUIRED")
    if status != HTTPStatus.PAYMENT_REQUIRED:
        return Answer(status, data=data)

    required = payment_required(challenge, data)
    offer = pick_offer(required, max_usd)
    price = int(offer["amount"]) / 10**USDC_DECIMALS
    if payer is None:
        return Answer(status, price_usd=price, data=data)

    hint = offer["extra"].get("recentBlockhash")
    if hint:
        blockhash = Hash.from_string(hint)
    else:
        latest = await rpc(
            session, rpc_endpoint, "getLatestBlockhash", [{"commitment": "confirmed"}]
        )
        blockhash = Hash.from_string(latest["value"]["blockhash"])
    header = build_payment_header(required, offer, payer, blockhash)

    async with session.request(
        method, url, json=body, headers={"PAYMENT-SIGNATURE": header}
    ) as response:
        status = response.status
        # The receipt first: a payment that settled is reported even when the
        # body that follows it is not JSON.
        receipt = response.headers.get("PAYMENT-RESPONSE")
        answer = await read_body(response)
    # Past this point the payment was sent: an unreadable receipt leaves the
    # transaction unknown, never the call unpaid.
    try:
        settled = json.loads(base64.b64decode(receipt)) if receipt else {}
    except ValueError:
        settled = {}
    return Answer(status, price, answer, settled.get("transaction"))


async def ask(  # noqa: PLR0913
    session: aiohttp.ClientSession,
    api: str,
    name: str,
    method: str,
    path: str,
    *,
    body: dict | None,
    calls: dict[str, Any],
) -> Answer | None:
    """`call_pumpdata`, or None when its offer is refused before signing.

    A refused offer (above --max-usd, another asset or network) is printed and
    skipped, so the other lookups still run and the total stays right.
    """
    try:
        return await call_pumpdata(session, api, method, path, body, **calls)
    except OfferRefusedError as err:
        print(f"\n{name}: refused, nothing signed: {err}")
        return None


async def first_signers(
    session: aiohttp.ClientSession, rpc_endpoint: str, mint: Pubkey, count: int
) -> list[str]:
    """The fee payers of the first successful transactions on a coin's curve.

    The first is the create, so its signer is the deployer. Returns an empty
    list when the curve has more history than MAX_SIGNATURE_PAGES can reach.
    """
    curve, _ = Pubkey.find_program_address(
        [b"bonding-curve", bytes(mint)], PUMP_PROGRAM
    )
    signatures: list[dict] = []
    before = None
    for _ in range(MAX_SIGNATURE_PAGES):
        options: dict[str, Any] = {"limit": SIGNATURE_PAGE, "commitment": "confirmed"}
        if before:
            options["before"] = before
        page = await rpc(
            session, rpc_endpoint, "getSignaturesForAddress", [str(curve), options]
        )
        signatures += page
        if len(page) < SIGNATURE_PAGE:
            break
        before = page[-1]["signature"]
    else:
        return []

    oldest = [s["signature"] for s in reversed(signatures) if s.get("err") is None]
    signers: list[str] = []
    for signature in oldest:
        if len(signers) > count:
            break
        tx = await rpc(
            session,
            rpc_endpoint,
            "getTransaction",
            [
                signature,
                {
                    "encoding": "json",
                    "commitment": "confirmed",
                    "maxSupportedTransactionVersion": 1,
                },
            ],
        )
        if tx is None:
            continue
        signer = tx["transaction"]["message"]["accountKeys"][0]
        if signer not in signers:
            signers.append(signer)
    return signers


def pct(share: float | None) -> str:
    """A 0..1 share as a percentage, or `-` when the answer has none."""
    return "-" if share is None else f"{share * 100:.1f}%"


def print_launch(launch: dict) -> None:
    """Print a /launch answer's numbers."""
    deployer = launch.get("deployer") or {}
    bundle = launch.get("bundle_at_creation") or {}
    matches = launch.get("matches") or {}
    print(f"created:             {launch.get('created')} ({launch.get('age_s')} s ago)")
    print(f"deployer:            {deployer.get('address')}")
    print(f"  launches:          {deployer.get('launches')}")
    print(f"  graduations:       {deployer.get('graduations')}")
    best_peak = deployer.get("best_peak")
    print(
        f"  best peak:         {f'{best_peak}x' if best_peak is not None else 'none on record'}"
    )
    print(
        f"bundle at creation:  {bundle.get('buyers_first_10s')} buyers in the first 10 s"
    )
    print(f"  held:              {pct(bundle.get('supply_share'))} of the supply")
    print(
        f"insiders hold:       {pct(launch.get('insider_supply_share'))} of the supply"
    )
    print(f"curve progress:      {pct(launch.get('curve_progress'))}")
    print(f"launches like it:    {matches.get('n')}")
    print(f"  graduated:         {pct(matches.get('graduated_share'))}")
    peak = (matches.get("peak_day1") or {}).get("p50")
    close = (matches.get("close_day1") or {}).get("p50")
    print(f"  median 24 h peak:  {peak}x the market cap at this age")
    print(f"  median 24 h close: {close}x")
    as_of = (launch.get("freshness") or {}).get("data_as_of")
    print(f"data as of:          {as_of}")


def print_wallets(records: dict) -> None:
    """Print a /wallets answer, one line per wallet, then the count per class."""
    print(f"{'wallet':<44} {'class':<13} {'pnl SOL':>10} {'in SOL':>10} {'coins':>7}")
    counts: dict[str, int] = {}
    for address, record in records.items():
        label = record.get("class", "-")
        counts[label] = counts.get(label, 0) + 1
        print(
            f"{address:<44} {label:<13} {record.get('pnl_sol', 0):>10.2f} "
            f"{record.get('put_in', 0):>10.2f} {record.get('coins', 0):>7}"
        )
    print("by class: " + ", ".join(f"{n} {label}" for label, n in counts.items()))


def print_json(data: dict) -> None:
    """Print an answer as it came back."""
    print(json.dumps(data, indent=2))


def report(name: str, answer: Answer, *, paying: bool) -> bool:
    """Print a call's status line; True when the answer has data to print."""
    price = f"${answer.price_usd}" if answer.price_usd is not None else "-"
    if answer.status == HTTPStatus.OK:
        receipt = f", paid in {answer.receipt}" if answer.receipt else ""
        print(f"\n{name}: {price}{receipt}")
        return True
    if answer.status == HTTPStatus.PAYMENT_REQUIRED and not paying:
        print(f"{name}: {price} (not paid; run with --pay)")
    elif answer.status == HTTPStatus.PAYMENT_REQUIRED:
        reason = (answer.data or {}).get("reason") or (answer.data or {}).get("error")
        print(f"\n{name}: payment refused, nothing settled: {reason}")
    elif answer.status == HTTPStatus.NOT_FOUND:
        print(f"\n{name}: not built yet, nothing charged; retry later")
    else:
        print(f"\n{name}: HTTP {answer.status}: {answer.data}")
    return False


def cost(answer: Answer, *, paying: bool) -> float:
    """What a call cost when paying, or would cost when not."""
    if paying:
        return answer.price_usd or 0 if answer.status == HTTPStatus.OK else 0
    return answer.price_usd or 0


async def check(  # noqa: PLR0913
    mint: Pubkey,
    *,
    api: str,
    buyers: int,
    wallets: list[str],
    deployer: bool,
    similar: bool,
    pay: bool,
    max_usd: float,
) -> None:
    """Run the pre-buy lookups for one coin and print what comes back."""
    payer = Keypair.from_bytes(base58.b58decode(PRIVATE_KEY)) if pay else None
    if (pay or buyers) and not RPC_ENDPOINT:
        raise SystemExit("Set SOLANA_NODE_RPC_ENDPOINT in .env, or pass --buyers 0")  # noqa: TRY003
    calls = {"rpc_endpoint": RPC_ENDPOINT, "max_usd": max_usd, "payer": payer}
    total = 0.0

    async with aiohttp.ClientSession() as session:
        signers = []
        if buyers:
            signers = await first_signers(session, RPC_ENDPOINT, mint, buyers)
            if not signers:
                print("The curve's history is too long to reach its first buyers.")
        addresses = list(dict.fromkeys([*signers, *wallets]))[:MAX_WALLETS]

        creator = signers[0] if signers else None
        name = "GET /launch"
        launch = await ask(
            session, api, name, "GET", f"/launch/{mint}", body=None, calls=calls
        )
        total += cost(launch, paying=pay) if launch else 0
        if launch and report(name, launch, paying=pay):
            print_launch(launch.data)
            creator = (launch.data.get("deployer") or {}).get("address") or creator

        # Each optional call: (shown as, method, path, body, how to print it).
        lookups = []
        if addresses:
            body = {"addresses": addresses, "mint": str(mint)}
            lookups.append(
                (
                    f"POST /wallets ({len(addresses)})",
                    "POST",
                    "/wallets",
                    body,
                    print_wallets,
                )
            )
        if deployer and creator:
            lookups.append(
                ("GET /deployer", "GET", f"/deployer/{creator}", None, print_json)
            )
        if similar:
            lookups.append(
                ("GET /similar", "GET", f"/similar/{mint}", None, print_json)
            )

        for name, method, path, body, show in lookups:
            answer = await ask(session, api, name, method, path, body=body, calls=calls)
            total += cost(answer, paying=pay) if answer else 0
            if answer and report(name, answer, paying=pay):
                show(answer.data)

    print(f"\n{'spent' if pay else 'would cost'}: ${total:.3f}")


def main() -> None:
    """Parse the command line and run the lookups."""
    parser = argparse.ArgumentParser(
        description="Look up a pump.fun coin on pumpdata.fun before buying it"
    )
    parser.add_argument("mint", help="The coin's mint address")
    parser.add_argument(
        "--pay",
        action="store_true",
        help="Pay each call in USDC from SOLANA_PRIVATE_KEY's wallet; "
        "without it, print the prices and spend nothing",
    )
    parser.add_argument(
        "--buyers",
        type=int,
        default=DEFAULT_BUYERS,
        help="How many of the curve's first signers to look up, after the "
        f"deployer; 0 reads nothing from RPC (default {DEFAULT_BUYERS})",
    )
    parser.add_argument(
        "--wallet",
        action="append",
        default=[],
        help="Another wallet to look up; repeat for more (50 in all)",
    )
    parser.add_argument(
        "--deployer", action="store_true", help="Also GET /deployer ($0.005)"
    )
    parser.add_argument(
        "--similar", action="store_true", help="Also GET /similar ($0.005)"
    )
    parser.add_argument(
        "--max-usd",
        type=float,
        default=DEFAULT_MAX_USD,
        help=f"Refuse to pay any one call more than this (default {DEFAULT_MAX_USD})",
    )
    parser.add_argument(
        "--api", default=DEFAULT_API, help=f"API base URL (default {DEFAULT_API})"
    )
    args = parser.parse_args()

    asyncio.run(
        check(
            Pubkey.from_string(args.mint),
            api=args.api.rstrip("/"),
            buyers=args.buyers,
            wallets=[str(Pubkey.from_string(w)) for w in args.wallet],
            deployer=args.deployer,
            similar=args.similar,
            pay=args.pay,
            max_usd=args.max_usd,
        )
    )


if __name__ == "__main__":
    main()
