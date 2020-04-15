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

module Signing 

# TODO: use libsodium base64-encoding instead since it offers a
# url-safe option to match cargo-crev:
# https://github.com/crev-dev/cargo-crev/blob/89982a281d53316e489c4214e60b618e312fe7e2/crev-common/src/lib.rs#L50
using Base64: base64encode, base64decode
using Sodium: LibSodium
const LS = LibSodium

export PublicKey, KeyPair, sign!, sign, verify

abstract type Key end

"Represent an ed25519 public key."
mutable struct PublicKey <: Key
    data::NTuple{LS.crypto_sign_ed25519_PUBLICKEYBYTES % Int, Cuchar}
end

mutable struct SecretKey <: Key
    data::NTuple{LS.crypto_sign_ed25519_SECRETKEYBYTES % Int, Cuchar}
end

# Need to treat it as a Ptr{Cuchar} when working with the key
Base.unsafe_convert(::Type{Ptr{Cuchar}}, k::Key) =
    convert(Ptr{Cuchar}, pointer_from_objref(k))
# Need to treat it as a Ptr{Cvoid} when shredding
Base.unsafe_convert(::Type{Ptr{Cvoid}}, k::Key) = pointer_from_objref(k)

Base.shred!(k::Key) = GC.@preserve k LS.sodium_memzero(k, sizeof(k))

"""
    KeyPair()

Generate an ed25519 keypair.
"""
struct KeyPair
    pk::PublicKey
    sk::SecretKey
end

function KeyPair()
    pk = PublicKey(ntuple(_-> 0x00, Val(LS.crypto_sign_ed25519_PUBLICKEYBYTES % Int)))
    sk = SecretKey(ntuple(_-> 0x00, Val(LS.crypto_sign_ed25519_SECRETKEYBYTES % Int)))
    finalizer(Base.shred!, sk)

    GC.@preserve pk sk LS.crypto_sign_ed25519_keypair(pk, sk)
    KeyPair(pk, sk)
end

"""
    sign!(sig, text, secretkey)

Sign `text` with ed25519 `secretkey` and store signature in `sig`.
"""
function sign!(sig::Vector{Cuchar}, text, sk::SecretKey)
    @assert sizeof(sig) == LS.crypto_sign_ed25519_BYTES
    l = Ref{UInt64}()
    GC.@preserve sig text sk LS.crypto_sign_ed25519_detached(
        sig, l, text, sizeof(text), sk)
    resize!(sig, l[])
end

"""
    sign(text, secretkey)

Return a base64-encoded signature for `text` signed by ed25519 `secretkey`.
"""
function sign(text, sk::SecretKey)
    sig = Vector{Cuchar}(undef, LS.crypto_sign_ed25519_BYTES)
    sign!(sig, text, sk)
    base64encode(sig)
end

"""
    verify(sig, text, publickey)

Return `true` if `sig` is a valid signature of `text` by ed25519 `publickey`.

If `sig` is an `AbstractString`, it is assumed to be base64-encoded.
"""
function verify(sig::Vector{Cuchar}, text, pk::PublicKey)
    @assert sizeof(sig) == LS.crypto_sign_ed25519_BYTES
    0 == GC.@preserve sig text pk LS.crypto_sign_ed25519_verify_detached(
        sig, text, sizeof(text), pk)
end

verify(sig::AbstractString, text, pk::PublicKey) =
    verify(base64decode(sig), text, pk)

end # module
