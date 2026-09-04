# Status codes mirrored from the libitb C ABI
# (cmd/cshared/internal/capi/errors.go). Numeric values are stable
# across releases.

const STATUS_OK = 0
const STATUS_BAD_HASH = 1
const STATUS_BAD_KEY_BITS = 2
const STATUS_BAD_HANDLE = 3
const STATUS_BAD_INPUT = 4
const STATUS_BUFFER_TOO_SMALL = 5
const STATUS_ENCRYPT_FAILED = 6
const STATUS_DECRYPT_FAILED = 7
const STATUS_SEED_WIDTH_MIX = 8
const STATUS_BAD_MAC = 9
const STATUS_MAC_FAILURE = 10
const STATUS_BLOB_MALFORMED_RECIPE = 11
const STATUS_RECIPE_PRIMITIVE_UNKNOWN = 12
const STATUS_UNKNOWN_PROFILE = 13
const STATUS_BLOB_MODE_MISMATCH = 19
const STATUS_BLOB_MALFORMED = 20
const STATUS_BLOB_VERSION_TOO_NEW = 21
const STATUS_BLOB_TOO_MANY_OPTS = 22
const STATUS_STREAM_TRUNCATED = 23
const STATUS_STREAM_AFTER_FINAL = 24
const STATUS_TRIPLE_CLOSED = 25
const STATUS_PROFILE_EXISTS = 26
const STATUS_INTERNAL = 99

const _STATUS_LABELS = Dict{Int,String}(
    STATUS_OK => "ok",
    STATUS_BAD_HASH => "unknown hash name",
    STATUS_BAD_KEY_BITS => "invalid key bits",
    STATUS_BAD_HANDLE => "invalid handle",
    STATUS_BAD_INPUT => "invalid input",
    STATUS_BUFFER_TOO_SMALL => "output buffer too small",
    STATUS_ENCRYPT_FAILED => "encrypt failed",
    STATUS_DECRYPT_FAILED => "decrypt failed",
    STATUS_SEED_WIDTH_MIX => "seed width mismatch",
    STATUS_BAD_MAC => "unknown MAC name or invalid MAC handle",
    STATUS_MAC_FAILURE => "MAC verification failed",
    STATUS_BLOB_MALFORMED_RECIPE => "blob profile record invalid",
    STATUS_RECIPE_PRIMITIVE_UNKNOWN =>
        "blob profile record names a primitive absent from the local registries",
    STATUS_UNKNOWN_PROFILE => "unknown profile name",
    STATUS_BLOB_MODE_MISMATCH => "blob mode mismatch",
    STATUS_BLOB_MALFORMED => "malformed state blob",
    STATUS_BLOB_VERSION_TOO_NEW => "blob version too new",
    STATUS_BLOB_TOO_MANY_OPTS => "too many blob export opts",
    STATUS_STREAM_TRUNCATED => "stream truncated before terminator",
    STATUS_STREAM_AFTER_FINAL => "stream chunk after terminator",
    STATUS_TRIPLE_CLOSED => "Triple Pipeline is closed",
    STATUS_PROFILE_EXISTS => "profile name already registered",
    STATUS_INTERNAL => "internal error",
)

"""
    status_label(code::Integer) -> String

Short human-readable label for a libitb status code; unknown codes
collapse to `"unknown status"`.
"""
status_label(code::Integer) = get(_STATUS_LABELS, Int(code), "unknown status")

"""
    ITBError <: Exception

Raised on every failed libitb call.

`status_code` carries the libitb status integer when the failure came
from the shared library (`-1` for binding-side failures such as a
library-load error). `last_error` carries the `ITB_LastError`
diagnostic captured immediately after the failing call
(process-global last-write-wins — the message may belong to a
different call under concurrent FFI use; the status code is always
attributable).
"""
struct ITBError <: Exception
    status_code::Int
    last_error::String
end

# Binding-side failure (no libitb status available).
ITBError(message::AbstractString) = ITBError(-1, String(message))

function Base.showerror(io::IO, e::ITBError)
    if e.status_code < 0
        print(io, "itb: ", e.last_error)
    elseif isempty(e.last_error)
        print(io, "itb: status=", e.status_code, " (", status_label(e.status_code), ")")
    else
        print(io, "itb: status=", e.status_code, " (", status_label(e.status_code),
              "): ", e.last_error)
    end
end
