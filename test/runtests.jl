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

using Test, Crev

const review1 = """
-----BEGIN CREV PACKAGE REVIEW-----
version: -1
date: "2018-12-18T23:10:21.111854021-08:00"
from:
    id-type: crev
    id: FYlr8YoYGVvDwHQxqEIs89reKKDy-oWisoO0qXXEfHE
    url: "https://github.com/dpc/crev-proofs"
package:
    source: "https://crates.io"
    name: log
    version: 0.4.6
    digest: BhDmOOjfESqs8i3z9qsQANH8A39eKklgQKuVtrwN-Tw
review:
    thoroughness: low
    understanding: medium
    rating: positive
-----BEGIN CREV PACKAGE REVIEW SIGNATURE-----
4R2WjtU-avpBznmJYAl44H1lOYgETu3RSNhCDcB4GpqhJbSRkd-eqnUuhHgDUs77OlhUf7BSA0dydxaALwx0Dg
-----END CREV PACKAGE REVIEW-----
"""

@testset "Proof Stream" begin
    # Test that we can iterate through the right number of proofs
    count = 0
    for review in ProofStream(IOBuffer(review1))
        count += 1
    end
    @test count == 1
    count = 0
    for review in ProofStream(IOBuffer(review1^3))
        count += 1
    end
    @test count == 3
end

@testset "Signing" begin
    kp = Crev.Signing.KeyPair()
    @test any(b-> b != 0x00, kp.pk.data)
    @test any(b-> b != 0x00, kp.sk.data)
    Base.shred!(kp.pk)
    @test all(b-> b === 0x00, kp.pk.data)
    finalize(kp.sk)
    @test all(b-> b === 0x00, kp.sk.data)
end
