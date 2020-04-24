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

struct MalformedProof{E<:Exception}
    err::E
end

function Proof(yaml::AbstractString, sig::AbstractString)
    parsed_yaml = try
        YAML.load(yaml)
    catch e
        return MalformedProof(e)
    end

    id_okay = haskey(parsed_yaml, "from") && let from = parsed_yaml["from"]
        haskey(from, "id-type") &&
        haskey(from, "id") &&
        haskey(from, "url") &&
        from["id-type"] == "crev" &&
        from["id"] isa AbstractString &&
        from["url"] isa AbstractString
    end
    if id_okay
        id = CrevID(Signing.PublicKey(parsed_yaml["from"]["id"]), parsed_yaml["from"]["url"])
    else
        return MalformedProof(ErrorException("Can't parse \"from\" field of YAML."))
    end

    Signing.verify(sig, yaml, id.id) ||
        return MalformedProof(ErrorException("Failed to verify Proof signature."))

    package_okay = haskey(parsed_yaml, "package") && let pkg = parsed_yaml["package"]
        haskey(pkg, "source") &&
        haskey(pkg, "name") &&
        haskey(pkg, "version") &&
        haskey(pkg, "digest") &&
        pkg["source"] isa AbstractString &&
        pkg["name"] isa AbstractString &&
        pkg["version"] isa AbstractString &&
        pkg["digest"] isa AbstractString &&
        (!haskey(pkg, "revision") || pkg["revision"] isa AbstractString)
    end
    if package_okay
        v = try
            VersionNumber(parsed_yaml["package"]["version"])
        catch e
            return MalformedProof(e)
        end
        package = Package(
            parsed_yaml["package"]["source"],
            parsed_yaml["package"]["name"],
            v,
            get(parsed_yaml["package"], "revision", nothing),
            parsed_yaml["package"]["digest"])
    else
        return MalformedProof(ErrorException("Can't parse \"package\" field of YAML."))
    end
    
    review_okay = haskey(parsed_yaml, "review") && let rev = parsed_yaml["review"]
        haskey(rev, "thoroughness") &&
        haskey(rev, "understanding") &&
        haskey(rev, "rating") &&
        rev["thoroughness"] isa AbstractString &&
        rev["understanding"] isa AbstractString &&
        rev["rating"] isa AbstractString
    end
    if review_okay
        review = Review(parsed_yaml["review"]["thoroughness"],
                        parsed_yaml["review"]["understanding"],
                        parsed_yaml["review"]["rating"])
    else
        return MalformedProof(ErrorException("Can't parse \"review\" field of YAML."))
    end
    
    toplevel_okay = haskey(parsed_yaml, "version") && parsed_yaml["version"] == -1 &&
        haskey(parsed_yaml, "date") && parsed_yaml["date"] isa AbstractString
    if toplevel_okay
        return Proof(parsed_yaml["version"], parsed_yaml["date"], id, package, review)
    else
        return MalformedProof(ErrorException("Can't parse top level fields of YAML."))
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
