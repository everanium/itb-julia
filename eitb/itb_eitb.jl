# eitb — command-line demonstrator for the ITB Julia binding.
#
# Subcommands:
#
#   itb_eitb.jl version                                   library + binding versions
#   itb_eitb.jl profiles                                  registered profile catalogue
#   itb_eitb.jl inspect <blob-hex>                        profile record of a blob
#   itb_eitb.jl encrypt <profile> <in-file> <out-file>    Single Message encrypt
#   itb_eitb.jl decrypt <profile> <blob-hex> <in-file> <out-file>
#
# `encrypt` prints the session blob (`save`) to stderr as hex; feed
# that hex back to `decrypt` on the receiving side, which reopens the
# session with `load` (the profile argument only routes Single
# Message versus streaming). `profiles` lists the registered profile
# catalogue one name per line; the profiles that carry a cipher
# surface are the ones `encrypt` / `decrypt` accept.

using ITB

const USAGE = """
usage: eitb version
       eitb profiles
       eitb inspect <blob-hex>
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>"""

function cmd_version()
    println("libitb ", version())
    println("itb-julia ", ITB.BINDING_VERSION)
end

function cmd_profiles()
    foreach(println, profiles())
end

function blob_from_hex(blob_hex::String)::Vector{UInt8}
    try
        return hex2bytes(blob_hex)
    catch e
        throw(ITBError("blob hex: $(sprint(showerror, e))"))
    end
end

cmd_inspect(blob_hex::String) = println(inspect(blob_from_hex(blob_hex)))

# Profiles whose canonical name begins with "streaming-" route
# through the one-shot streaming buffered pair instead of the Single
# Message pair.
is_streaming_profile(profile::AbstractString) = startswith(profile, "streaming-")

# Recursively create the parent directory of `path` (mkdir -p).
function ensure_parent_dir(path::AbstractString)
    parent = dirname(path)
    if !isempty(parent)
        mkpath(parent)
    end
end

function cmd_encrypt(profile::String, infile::String, outfile::String)
    plain = read(infile)
    pipe = Pipeline(profile)
    try
        wire = is_streaming_profile(profile) ?
            encrypt_stream_one_shot(pipe, plain) :
            encrypt_message(pipe, plain)
        ensure_parent_dir(outfile)
        write(outfile, wire)
        println(stderr, bytes2hex(save(pipe)))
        println("encrypted $infile -> $outfile ($(length(plain)) -> $(length(wire)) bytes)")
    finally
        free!(pipe)
    end
end

function cmd_decrypt(profile::String, blob_hex::String, infile::String, outfile::String)
    session_blob = blob_from_hex(blob_hex)
    wire = read(infile)
    pipe = load(session_blob)
    try
        plain = is_streaming_profile(profile) ?
            decrypt_stream_one_shot(pipe, wire) :
            decrypt_message(pipe, wire)
        ensure_parent_dir(outfile)
        write(outfile, plain)
        println("decrypted $infile -> $outfile ($(length(wire)) -> $(length(plain)) bytes)")
    finally
        free!(pipe)
    end
end

function main(argv::Vector{String})::Int
    known_shape =
        (length(argv) == 1 && argv[1] in ("version", "profiles")) ||
        (length(argv) == 2 && argv[1] == "inspect") ||
        (length(argv) == 4 && argv[1] == "encrypt") ||
        (length(argv) == 5 && argv[1] == "decrypt")
    if !known_shape
        println(stderr, USAGE)
        return 2
    end
    try
        # Go-runtime pacing caps applied before any cipher work.
        set_memory_limit(512 << 20)
        set_gc_percent(20)
        if argv[1] == "version"
            cmd_version()
        elseif argv[1] == "profiles"
            cmd_profiles()
        elseif argv[1] == "inspect"
            cmd_inspect(argv[2])
        elseif argv[1] == "encrypt"
            cmd_encrypt(argv[2], argv[3], argv[4])
        else
            cmd_decrypt(argv[2], argv[3], argv[4], argv[5])
        end
    catch e
        (e isa ITBError || e isa SystemError || e isa Base.IOError) || rethrow()
        println(stderr, "eitb: ", sprint(showerror, e))
        return 1
    end
    return 0
end

exit(main(collect(String, ARGS)))
