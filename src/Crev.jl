module Crev

export ProofStream

struct Proof end

"""
    ProofStream(io)

Construct an iterator which yields crev proofs.
"""
struct ProofStream{T<:IO}
    io::T
end

Base.IteratorSize(::Type{ProofStream}) = Base.SizeUnknown()
Base.eltype(::Type{ProofStream}) = Proof

function Base.iterate(ps::ProofStream, state=nothing)
    readuntil(ps.io, "-----BEGIN CREV PACKAGE REVIEW-----")
    yaml = readuntil(ps.io, "-----BEGIN CREV PACKAGE REVIEW SIGNATURE-----")
    sig = readuntil(ps.io,  "-----END CREV PACKAGE REVIEW-----")

    if isempty(yaml) || isempty(sig)
        nothing
    else
        (Proof(), nothing)
    end
end

end # module
