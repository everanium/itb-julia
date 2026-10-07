# Status codes mirrored from the libitb3 C ABI
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

"""
    ITBError <: Exception

Raised on every failed libitb3 call.

`status_code` carries the libitb3 status integer when the failure came
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

# Binding-side failure (no libitb3 status available).
ITBError(message::AbstractString) = ITBError(-1, String(message))

function Base.showerror(io::IO, e::ITBError)
    if e.status_code < 0
        print(io, "itb: ", e.last_error)
    else
        print(io, "itb: status=", e.status_code, ": ", e.last_error)
    end
end
