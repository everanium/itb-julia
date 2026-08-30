# eitb — command-line demonstrator for the ITB Julia binding.
#
# Subcommands:
#
#   itb_eitb.jl version                                   library + binding versions
#   itb_eitb.jl hashes                                    shipped hash primitive roster
#   itb_eitb.jl encrypt <profile> <in-file> <out-file>    Single Message encrypt
#   itb_eitb.jl decrypt <profile> <blob-hex> <in-file> <out-file>
#
# `encrypt` prints the session blob to stderr as hex; feed that hex
# back to `decrypt` on the receiving side.

using ITB

const USAGE = """
usage: eitb version
       eitb hashes
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>"""

function cmd_version()
    println("libitb ", version())
    println("itb-julia ", ITB.BINDING_VERSION)
end

function cmd_hashes()
    for (i, h) in enumerate(hashes())
        println(lpad(string(i - 1), 2), "  ", rpad(h.name, 12), " ", h.width, " bits")
    end
end

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
        println(stderr, bytes2hex(blob(pipe)))
        println("encrypted $infile -> $outfile ($(length(plain)) -> $(length(wire)) bytes)")
    finally
        free!(pipe)
    end
end

function cmd_decrypt(profile::String, blob_hex::String, infile::String, outfile::String)
    session_blob = try
        hex2bytes(blob_hex)
    catch e
        throw(ITBError("blob hex: $(sprint(showerror, e))"))
    end
    wire = read(infile)
    pipe = Pipeline(profile; blob=session_blob)
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
        (length(argv) == 1 && argv[1] in ("version", "hashes")) ||
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
        elseif argv[1] == "hashes"
            cmd_hashes()
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
