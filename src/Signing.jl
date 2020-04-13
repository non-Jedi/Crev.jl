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

export PublicKey, KeyPair

abstract type Key end

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

end # module
