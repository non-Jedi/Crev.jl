# This file is part of Crev.jl.
#
# Crev.jl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Crev.jl is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.

module Crev

export ProofStream

import YAML

include("Signing.jl")

const M{T} = Union{Nothing,T}

struct CrevID
    id::Signing.PublicKey
    url::String
end

struct Package
    source::String
    name::String
    version::VersionNumber
    revision::M{String}
    digest::String
end

# TODO: use some type of enum for the fields instead?
struct Review
    thoroughness::String
    understanding::String
    rating::String
end

struct Proof
    version::Int
    # TODO: parse this into a TimeZones.jl ZonedDateTime
    date::String
    id::CrevID
    package::Package
    review::Review
end

struct MalformedProof end

function Proof(yaml::AbstractString, sig::AbstractString)
    try
        parsed_yaml = YAML.load(yaml)

        # Ensure id-type is crev
        @assert parsed_yaml["from"]["id-type"] == "crev"
        id = CrevID(Signing.PublicKey(parsed_yaml["from"]["id"]), parsed_yaml["from"]["url"])

        if Signing.verify(sig, yaml, id.id)
            package = Package(
                parsed_yaml["package"]["source"],
                parsed_yaml["package"]["name"],
                VersionNumber(parsed_yaml["package"]["version"]),
                get(parsed_yaml["package"], "revision", nothing),
                parsed_yaml["package"]["digest"])

            review = Review(
                parsed_yaml["review"]["thoroughness"],
                parsed_yaml["review"]["understanding"],
                parsed_yaml["review"]["rating"])

            Proof(parsed_yaml["version"], parsed_yaml["date"], id, package, review)
        else
            MalformedProof()
        end
    catch e
        if e isa YAML.ParserError || e isa KeyError || e isa AssertionError
            return MalformedProof()
        else
            rethrow()
        end
    end
end

"""
    ProofStream(io)

Construct an iterator which yields crev proofs.
"""
struct ProofStream{T<:IO}
    io::T
end

Base.IteratorSize(::Type{ProofStream}) = Base.SizeUnknown()
Base.eltype(::Type{ProofStream}) = Union{Proof,MalformedProof}

function Base.iterate(ps::ProofStream, state=nothing)
    readuntil(ps.io, "-----BEGIN CREV PACKAGE REVIEW-----\n"; keep=true)
    yaml = readuntil(ps.io, "-----BEGIN CREV PACKAGE REVIEW SIGNATURE-----")
    readline(ps.io)
    sig = readline(ps.io)
    readuntil(ps.io,  "-----END CREV PACKAGE REVIEW-----"; keep=true)

    if isempty(yaml) || isempty(sig)
        nothing
    else
        (Proof(yaml, sig), nothing)
    end
end

end # module
