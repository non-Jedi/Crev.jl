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

using Sodium: LibSodium
const LS = LibSodium

export PublicKey, KeyPair, sign!, sign, verify

"""
    base64encode(bin)

Return a `String` of data from `bin` base64-encoded.
"""
function base64encode(bin)
    b64_maxlen = LS.sodium_base64_ENCODED_LEN(
        sizeof(bin), LS.sodium_base64_VARIANT_URLSAFE_NO_PADDING)
    b64 = Vector{Cuchar}(undef, b64_maxlen)
    GC.@preserve bin b64 LS.sodium_bin2base64(
        pointer(b64), b64_maxlen, bin, sizeof(bin),
        LS.sodium_base64_VARIANT_URLSAFE_NO_PADDING)
    GC.@preserve b64 unsafe_string(pointer(b64))
end

"""
    base64decode!(bin, b64)

Decode base64-encoded `b64` and store the result in `bin`.
"""
function base64decode!(bin, b64)
    bin_len = Ref{Csize_t}()
    status = GC.@preserve bin b64 LS.sodium_base642bin(
        bin, sizeof(bin), b64, sizeof(b64), C_NULL, bin_len, C_NULL,
        LS.sodium_base64_VARIANT_URLSAFE_NO_PADDING)
    status == 0 || error("Unable to decode")
    bin_len[] == sizeof(bin) || resize!(bin, bin_len[])
end

"""
    base64decode(b64)

Decode base64-encoded `b64` and store results as `Vector{UInt8}`.
"""
function base64decode(b64)
    bin = Vector{UInt8}(undef, sizeof(b64))
    base64decode!(bin, b64)
    bin
end

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

function KeyPair(pk::AbstractString, sk::AbstractString)
    _pk = PublicKey(ntuple(_-> 0x00, Val(LS.crypto_sign_ed25519_PUBLICKEYBYTES % Int)))
    _sk = SecretKey(ntuple(_-> 0x00, Val(LS.crypto_sign_ed25519_SECRETKEYBYTES % Int)))
    GC.@preserve _pk base64decode!(_pk, pk)
    GC.@preserve _sk base64decode!(_sk, sk)
    KeyPair(_pk, _sk)
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
