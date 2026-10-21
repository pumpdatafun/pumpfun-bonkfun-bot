"""Verify the pumpdata lookup pays only when asked, at most once, and as offered.

`cookbook/pumpfun/read/pumpfun_check_token_pumpdata.py` pays for each call over
x402: the server answers 402 with an offer, the script signs a USDC transfer
and retries with it in a `PAYMENT-SIGNATURE` header. Every way that goes wrong
costs money or leaks a signature:

- paying when the caller asked only for the price;
- paying again after the server refused a payment, or for an offer above the
  caller's cap, in another asset, or on another network;
- signing a transaction the facilitator cannot complete: the fee payer must be
  the offer's `feePayer`, left unsigned, with the wallet signing as the transfer
  authority only;
- reading the first buyers newest first, which is what the RPC returns.

Offline machine checks against a stub HTTP session, with a throwaway keypair
that holds nothing. No network, nothing signed for the chain, no funds moved:

  1. Without a payer, a 402 comes back with its price and nothing is signed.
  2. With a payer, the retry carries one v0 transaction: fee payer = the
     offer's feePayer with an empty signature, the payer's signature valid,
     ComputeBudget limit and price, a USDC TransferChecked of the offered
     amount from the payer's ATA to payTo's, and a memo; `accepted` echoes the
     offer, and the receipt is read from PAYMENT-RESPONSE.
  3. A paid call answered 402 again is not paid a second time.
  4. Offers above the cap, in another asset, on another network, without a
     fee payer, or naming the payer as fee payer are refused before signing.
  5. A 404 costs nothing; an unpaid 402 is counted as what it would cost.
  6. A paid call whose reply is not JSON still returns its receipt; an offer
     refused before signing is skipped by `ask`, not raised; an unreadable
     receipt after paying is a paid answer, not a refusal.
  7. An offer carried only in the PAYMENT-REQUIRED header is read and paid.
  8. A paid request that gets no reply is reported as possibly settled, not
     retried, and the closing line says so.
  9. A malformed offer (no list of offers, a null offer, extra not an object, an
     amount, payTo or feePayer that does not parse, a zero amount) is refused
     before anything is signed.
  10. A paid answer that is not a 200 but carries a receipt naming the transfer
      is counted as spent.
  11. Exactly MAX_SIGNATURE_PAGES full pages of curve history is the whole
      history (the first signers come back), not "too long".
  12. The wallets for POST /wallets: the first signers and --wallet; the
      deployer from /launch when buyers were asked for and could not be read;
      never added with --buyers 0.
  13. The first signers come back oldest first, failed transactions skipped,
     each wallet once, the create's signer first; a curve with more history
     than the script pages through gives none.

Usage:
    uv run tests/regression/verify_pumpdata_x402_payment.py
"""

import asyncio
import base64
import json
import struct
import sys
from collections.abc import Callable
from http import HTTPStatus
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "cookbook" / "pumpfun" / "read"))

import aiohttp  # noqa: E402
import pumpfun_check_token_pumpdata as check  # noqa: E402
from solders.hash import Hash  # noqa: E402
from solders.keypair import Keypair  # noqa: E402
from solders.message import to_bytes_versioned  # noqa: E402
from solders.pubkey import Pubkey  # noqa: E402
from solders.signature import Signature  # noqa: E402
from solders.transaction import VersionedTransaction  # noqa: E402
from spl.token.instructions import get_associated_token_address  # noqa: E402

API = "https://pumpdata.stub.invalid"
RPC = "https://rpc.stub.invalid"
PATH = "/launch/GftdnCVhNpmavB7Tymawkr8k5vjngU45ahKbnq17pump"
FEE_PAYER = str(Keypair().pubkey())
PAY_TO = str(Keypair().pubkey())
AMOUNT = 5000  # $0.005 in USDC's raw units
BLOCKHASH = str(Hash.new_unique())
RECEIPT = "5" * 88
COMPUTE_BUDGET_PROGRAM = Pubkey.from_string(
    "ComputeBudget111111111111111111111111111111"
)
MAX_COMPUTE_UNIT_PRICE = 5_000_000  # the facilitator's ceiling, micro-lamports
TRANSFER_CHECKED = 12
# The facilitator's fee payer, then the wallet paying.
SIGNERS = 2
X402_VERSION = 2
PRICE_USD = AMOUNT / 1e6


def offer(**changes: object) -> dict:
    """A 402 offer shaped like pumpdata's, with `changes` applied."""
    accepted = {
        "scheme": "exact",
        "network": check.SOLANA_MAINNET,
        "amount": str(AMOUNT),
        "asset": str(check.USDC_MINT),
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 120,
        "extra": {"name": "USDC", "feePayer": FEE_PAYER},
    }
    accepted.update(changes)
    return accepted


def payment_required(accepted: dict) -> dict:
    """A 402 body offering `accepted`."""
    return {
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": {"url": f"{API}{PATH}", "mimeType": "application/json"},
        "accepts": [accepted],
    }


class StubResponse:
    """Minimal stand-in for an aiohttp response."""

    def __init__(
        self, status: int, payload: dict | str, headers: dict | None = None
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self._payload = payload

    async def __aenter__(self) -> "StubResponse":
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def json(self, content_type: str | None = None) -> dict:  # noqa: ARG002
        """Return the scripted payload; a string payload is not JSON."""
        if isinstance(self._payload, str):
            return json.loads(self._payload)  # raises, as a page would
        return self._payload

    async def text(self) -> str:
        """Return the payload as text."""
        return (
            self._payload
            if isinstance(self._payload, str)
            else json.dumps(self._payload)
        )


class StubSession:
    """Answers pumpdata calls with `api` and JSON-RPC calls with `rpc`.

    Records every PAYMENT-SIGNATURE header it is sent.
    """

    def __init__(
        self,
        api: Callable[[dict], StubResponse],
        rpc: Callable[[str, list], object] | None = None,
    ) -> None:
        self.api = api
        self.rpc = rpc or (lambda _m, _p: {"value": {"blockhash": BLOCKHASH}})
        self.signatures: list[str] = []

    def request(
        self,
        _method: str,
        _url: str,
        json: dict | None = None,  # noqa: ARG002
        headers: dict | None = None,
    ) -> StubResponse:
        """Serve one pumpdata call."""
        headers = headers or {}
        if "PAYMENT-SIGNATURE" in headers:
            self.signatures.append(headers["PAYMENT-SIGNATURE"])
        return self.api(headers)

    def post(self, _url: str, json: dict) -> StubResponse:
        """Serve one JSON-RPC call."""
        return StubResponse(
            200,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": self.rpc(json["method"], json["params"]),
            },
        )


def paid_once(accepted: dict) -> Callable[[dict], StubResponse]:
    """402 until a payment arrives, then 200 with a receipt."""

    def answer(headers: dict) -> StubResponse:
        if "PAYMENT-SIGNATURE" not in headers:
            return StubResponse(402, payment_required(accepted))
        receipt = base64.b64encode(
            json.dumps({"success": True, "transaction": RECEIPT}).encode()
        ).decode()
        return StubResponse(200, {"ok": True}, {"PAYMENT-RESPONSE": receipt})

    return answer


async def call(
    session: StubSession, payer: Keypair | None, max_usd: float = 0.01
) -> check.Answer:
    """Run one GET through the script's x402 flow."""
    return await check.call_pumpdata(
        session, API, "GET", PATH, None, payer=payer, rpc_endpoint=RPC, max_usd=max_usd
    )


def report(label: str, ok: bool, detail: str = "") -> bool:  # noqa: FBT001
    """Print one check's outcome, with `detail` when it failed."""
    print(f"{label} -> OK" if ok else f"{label} -> FAIL: {detail}")
    return ok


async def check_unpaid_call_signs_nothing() -> bool:
    """Without a payer the price comes back and no payment is sent."""
    session = StubSession(paid_once(offer()))
    answer = await call(session, payer=None)
    ok = (
        answer.status == HTTPStatus.PAYMENT_REQUIRED
        and answer.price_usd == PRICE_USD
        and not session.signatures
    )
    return report("unpaid call reports the price, signs nothing", ok, str(answer))


async def check_payment_transaction_shape() -> bool:  # noqa: PLR0911
    """The one payment sent is the transaction the offer asks for."""
    payer = Keypair()
    session = StubSession(paid_once(offer()))
    answer = await call(session, payer=payer)
    label = "payment is the offered USDC transfer, fee payer left to the facilitator"
    if (
        answer.status != HTTPStatus.OK
        or answer.receipt != RECEIPT
        or len(session.signatures) != 1
    ):
        return report(
            label, ok=False, detail=f"{answer}, {len(session.signatures)} sent"
        )

    payload = json.loads(base64.b64decode(session.signatures[0]))
    if payload["x402Version"] != X402_VERSION or payload["accepted"] != offer():
        return report(label, ok=False, detail="accepted does not echo the offer")

    tx = VersionedTransaction.from_bytes(
        base64.b64decode(payload["payload"]["transaction"])
    )
    message = tx.message
    keys = message.account_keys
    if str(keys[0]) != FEE_PAYER or message.header.num_required_signatures != SIGNERS:
        return report(label, ok=False, detail="fee payer is not the offer's feePayer")
    if tx.signatures[0] != Signature.default():
        return report(label, ok=False, detail="fee payer slot is signed")
    if not tx.signatures[1].verify(payer.pubkey(), to_bytes_versioned(message)):
        return report(label, ok=False, detail="payer signature does not verify")
    if str(message.recent_blockhash) != BLOCKHASH:
        return report(label, ok=False, detail="blockhash not the RPC's")

    programs = [keys[ix.program_id_index] for ix in message.instructions]
    expected = [
        COMPUTE_BUDGET_PROGRAM,
        COMPUTE_BUDGET_PROGRAM,
        check.TOKEN_PROGRAM,
        check.MEMO_PROGRAM,
    ]
    if programs != expected:
        return report(label, ok=False, detail=f"instructions {programs}")

    price_data = bytes(message.instructions[1].data)
    if struct.unpack_from("<Q", price_data, 1)[0] > MAX_COMPUTE_UNIT_PRICE:
        return report(
            label, ok=False, detail="compute price above the facilitator's ceiling"
        )

    transfer = message.instructions[2]
    tag, amount, decimals = struct.unpack("<BQB", bytes(transfer.data))
    accounts = [keys[i] for i in transfer.accounts]
    want = [
        get_associated_token_address(payer.pubkey(), check.USDC_MINT),
        check.USDC_MINT,
        get_associated_token_address(Pubkey.from_string(PAY_TO), check.USDC_MINT),
        payer.pubkey(),
    ]
    ok = (tag, amount, decimals) == (TRANSFER_CHECKED, AMOUNT, 6) and accounts == want
    return report(
        label, ok, "" if ok else f"transfer {tag} {amount} {decimals} {accounts}"
    )


async def check_refused_payment_not_retried() -> bool:
    """A payment the server refuses is not followed by another one."""
    refused = payment_required(offer()) | {"error": "payment_invalid"}
    session = StubSession(lambda _h: StubResponse(402, refused))
    answer = await call(session, payer=Keypair())
    ok = (
        answer.status == HTTPStatus.PAYMENT_REQUIRED
        and len(session.signatures) == 1
        and answer.receipt is None
    )
    return report(
        "a refused payment is not paid again", ok, f"{len(session.signatures)} sent"
    )


async def check_bad_offers_refused_before_signing() -> bool:
    """Offers the script must not pay are refused with nothing signed."""
    payer = Keypair()
    bad = {
        "above the cap": offer(amount="20000"),
        "another asset": offer(asset=str(Keypair().pubkey())),
        "another network": offer(network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
        "no fee payer": offer(extra={"name": "USDC"}),
        "payer as fee payer": offer(extra={"feePayer": str(payer.pubkey())}),
    }
    failures = []
    for name, accepted in bad.items():
        session = StubSession(paid_once(accepted))
        try:
            await call(session, payer=payer)
            failures.append(f"{name}: paid")
        except check.OfferRefusedError:
            if session.signatures:
                failures.append(f"{name}: signed before refusing")
    return report(
        "bad offers refused before signing", not failures, "; ".join(failures)
    )


async def check_costs() -> bool:
    """A 404 is free; a 402 not paid counts as what it would cost."""
    not_found = check.Answer(404)
    quoted = check.Answer(402, price_usd=PRICE_USD)
    paid = check.Answer(200, price_usd=PRICE_USD, receipt=RECEIPT)
    ok = (
        check.cost(not_found, paying=True) == 0
        and check.cost(quoted, paying=True) == 0
        and check.cost(quoted, paying=False) == PRICE_USD
        and check.cost(paid, paying=True) == PRICE_USD
    )
    return report("only answered calls count as spent", ok)


async def check_bad_replies_do_not_lose_the_payment() -> bool:
    """A non-JSON reply after paying keeps the receipt; a refused offer is skipped."""
    paid = paid_once(offer())

    def gateway_page(headers: dict) -> StubResponse:
        answer = paid(headers)
        if "PAYMENT-SIGNATURE" in headers:
            return StubResponse(502, "<html>Bad Gateway</html>", answer.headers)
        return answer

    answer = await call(StubSession(gateway_page), payer=Keypair())
    kept = answer.receipt == RECEIPT and "Bad Gateway" in answer.data["error"]
    session = StubSession(paid_once(offer(amount="20000")))
    calls = {"payer": Keypair(), "rpc_endpoint": RPC, "max_usd": 0.01}
    skipped = await check.ask(session, API, "GET", "GET", PATH, body=None, calls=calls)
    garbled = await check.ask(
        StubSession(garbled_receipt(offer())),
        API,
        "GET",
        "GET",
        PATH,
        body=None,
        calls=calls | {"max_usd": 0.01},
    )
    paid_anyway = (
        garbled is not None
        and garbled.status == HTTPStatus.OK
        and check.cost(garbled, paying=True) == PRICE_USD
    )
    ok = kept and skipped is None and not session.signatures and paid_anyway
    return report(
        "non-JSON reply keeps the receipt; refused offer skipped; bad receipt paid",
        ok,
        f"{answer} {skipped} {garbled}",
    )


def garbled_receipt(accepted: dict) -> Callable[[dict], StubResponse]:
    """402 until a payment arrives, then 200 with a receipt that is not JSON."""

    def answer(headers: dict) -> StubResponse:
        if "PAYMENT-SIGNATURE" not in headers:
            return StubResponse(402, payment_required(accepted))
        return StubResponse(200, {"ok": True}, {"PAYMENT-RESPONSE": "bm90IGpzb24="})

    return answer


async def check_offer_read_from_header() -> bool:
    """A 402 with the offer only in PAYMENT-REQUIRED (empty body) is paid."""
    paid = paid_once(offer())
    challenge = base64.b64encode(
        json.dumps(payment_required(offer())).encode()
    ).decode()

    def header_only(headers: dict) -> StubResponse:
        if "PAYMENT-SIGNATURE" not in headers:
            return StubResponse(402, {}, {"PAYMENT-REQUIRED": challenge})
        return paid(headers)

    session = StubSession(header_only)
    answer = await call(session, payer=Keypair())
    ok = (
        answer.status == HTTPStatus.OK
        and answer.receipt == RECEIPT
        and len(session.signatures) == 1
    )
    return report("offer read from the PAYMENT-REQUIRED header", ok, str(answer))


async def check_no_reply_after_paying() -> bool:
    """A paid request with no reply is possibly settled: flagged, not retried."""
    lost = StubSession(no_reply_after_paying(offer()))
    unknown = await call(lost, payer=Keypair())
    line = check.summary([unknown], paying=True)
    ok = (
        unknown.payment_unknown
        and len(lost.signatures) == 1
        and line
        == "spent: $0.000; $0.005 more may have settled (no reply after paying)"
    )
    return report(
        "no reply after paying is reported as possibly settled",
        ok,
        f"{unknown} {line}",
    )


def no_reply_after_paying(accepted: dict) -> Callable[[dict], StubResponse]:
    """402 until a payment arrives, then the connection drops."""

    def answer(headers: dict) -> StubResponse:
        if "PAYMENT-SIGNATURE" in headers:
            raise aiohttp.ServerDisconnectedError
        return StubResponse(402, payment_required(accepted))

    return answer


async def check_malformed_offers_refused() -> bool:
    """Offers that do not parse are refusals, raised before signing."""
    good = offer()
    cases = {
        "no list of offers": {"x402Version": 2, "accepts": "x"},
        "a null offer": {"x402Version": 2, "accepts": [None]},
        "extra not an object": payment_required(offer(extra=["x"])),
        "amount not a number": payment_required(offer(amount="abc")),
        "zero amount": payment_required(offer(amount="0")),
        "payTo not an address": payment_required(offer(payTo="not-a-key")),
        "feePayer not an address": payment_required(offer(extra={"feePayer": "bad"})),
    }
    failures = []
    for name, body in cases.items():
        session = StubSession(lambda _h, body=body: StubResponse(402, body))
        try:
            await call(session, payer=Keypair())
            failures.append(f"{name}: paid")
        except check.OfferRefusedError:
            if session.signatures:
                failures.append(f"{name}: signed before refusing")
        except Exception as err:  # noqa: BLE001
            failures.append(f"{name}: {type(err).__name__}")
    # the good offer still goes through
    ok_session = StubSession(paid_once(good))
    answer = await call(ok_session, payer=Keypair())
    if answer.status != HTTPStatus.OK:
        failures.append(f"a good offer: {answer}")
    return report(
        "malformed offers refused before signing", not failures, "; ".join(failures)
    )


async def check_receipt_on_error_counts() -> bool:
    """A non-200 paid answer whose receipt names the transfer counts as spent."""
    paid = paid_once(offer())

    def settled_then_500(headers: dict) -> StubResponse:
        answer = paid(headers)
        if "PAYMENT-SIGNATURE" in headers:
            return StubResponse(500, {"error": "internal"}, answer.headers)
        return answer

    answer = await call(StubSession(settled_then_500), payer=Keypair())
    line = check.summary([answer], paying=True)
    ok = (
        answer.status == HTTPStatus.INTERNAL_SERVER_ERROR
        and answer.receipt == RECEIPT
        and line == "spent: $0.005"
    )
    return report(
        "a receipt on a non-200 answer counts as spent", ok, f"{answer} {line}"
    )


async def check_page_boundary() -> bool:
    """Five full pages and an empty sixth is the whole history; a sixth with rows is not."""
    pages = check.MAX_SIGNATURE_PAGES
    size = check.SIGNATURE_PAGE

    def history(extra: int) -> Callable[[str, list], object]:
        calls = {"n": 0}

        def rpc(method: str, params: list) -> object:
            if method == "getSignaturesForAddress":
                n = calls["n"]
                calls["n"] += 1
                if (
                    n < pages
                ):  # newest first: page 0 has the newest, the last full page ends with the create
                    return [
                        {"signature": f"p{n}-{i}", "err": None} for i in range(size)
                    ]
                return [{"signature": f"x{i}", "err": None} for i in range(extra)]
            return {"transaction": {"message": {"accountKeys": [params[0]]}}}

        return rpc

    mint = Keypair().pubkey()
    whole = await check.first_signers(
        StubSession(paid_once(offer()), history(0)), RPC, mint, 1
    )
    longer = await check.first_signers(
        StubSession(paid_once(offer()), history(3)), RPC, mint, 1
    )
    oldest = f"p{pages - 1}-{size - 1}"
    second = f"p{pages - 1}-{size - 2}"
    ok = whole == [oldest, second] and longer == []
    return report(
        "five full pages is the whole history; more gives none", ok, f"{whole} {longer}"
    )


async def check_wallet_set() -> bool:
    """The /wallets set: signers and --wallet; the deployer only when buyers were not read."""
    ws = check.wallet_set
    ok = (
        ws(["d", "b1"], ["w"], "d", buyers=10) == ["d", "b1", "w"]
        and ws([], ["w"], "d", buyers=10) == ["d", "w"]
        and ws([], ["w"], "d", buyers=0) == ["w"]
        and ws([], [], "d", buyers=0) == []
        and ws([], [], None, buyers=10) == []
        and ws(["d"], ["d"], "d", buyers=10) == ["d"]
    )
    return report(
        "the /wallets set adds the deployer only when buyers were not read", ok
    )


async def check_first_signers_oldest_first() -> bool:
    """The first signers are read oldest first, skipping failures and repeats."""
    # Newest first, as getSignaturesForAddress returns them.
    history = [
        {"signature": "s6", "err": None},
        {"signature": "s5", "err": None},
        {"signature": "s4", "err": {"InstructionError": [0, "Custom"]}},
        {"signature": "s3", "err": None},
        {"signature": "s2", "err": None},
        {"signature": "s1", "err": None},  # the create
    ]
    signer = {
        "s1": "deployer",
        "s2": "buyer-a",
        "s3": "buyer-a",
        "s4": "failed",
        "s5": "buyer-b",
        "s6": "buyer-c",
    }

    def rpc(method: str, params: list) -> object:
        if method == "getSignaturesForAddress":
            return history
        return {"transaction": {"message": {"accountKeys": [signer[params[0]]]}}}

    mint = Keypair().pubkey()
    got = await check.first_signers(StubSession(paid_once(offer()), rpc), RPC, mint, 2)
    ok = got == ["deployer", "buyer-a", "buyer-b"]

    full_page = [
        {"signature": f"x{i}", "err": None} for i in range(check.SIGNATURE_PAGE)
    ]
    deep = await check.first_signers(
        StubSession(paid_once(offer()), lambda _m, _p: full_page), RPC, mint, 2
    )
    ok = ok and deep == []
    return report(
        "first signers oldest first; deep history gives none", ok, f"{got} {deep}"
    )


async def main() -> None:
    """Run every check and exit non-zero if any failed."""
    print("=" * 72)
    print("Verifying the pumpdata lookup pays only when asked, once, as offered")
    print("=" * 72)

    results = [
        await check_unpaid_call_signs_nothing(),
        await check_payment_transaction_shape(),
        await check_refused_payment_not_retried(),
        await check_bad_offers_refused_before_signing(),
        await check_costs(),
        await check_bad_replies_do_not_lose_the_payment(),
        await check_offer_read_from_header(),
        await check_no_reply_after_paying(),
        await check_malformed_offers_refused(),
        await check_receipt_on_error_counts(),
        await check_page_boundary(),
        await check_wallet_set(),
        await check_first_signers_oldest_first(),
    ]

    print("\n" + "=" * 72)
    if all(results):
        print(f"ALL {len(results)} CHECKS PASSED")
    else:
        print(f"{results.count(False)}/{len(results)} CHECKS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
