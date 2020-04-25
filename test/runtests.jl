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

using Test, Crev, YAML

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

const malformed_yaml = """
-----BEGIN CREV PACKAGE REVIEW-----
version -1
date: "2018-12-18T23:10:21.111854021-08:00"
from: hello
  id type: crev
  id: FYlr8YoYGVvDwHQxqEIs89reKKDy-oWisoO0qXXEfHE
  url: "https://github.com/dpc/crev-proofs"
package:
  source: "https://crates.io"
-----BEGIN CREV PACKAGE REVIEW SIGNATURE-----
4R2WjtU-avpBznmJYAl44H1lOYgETu3RSNhCDcB4GpqhJbSRkd-eqnUuhHgDUs77OlhUf7BSA0dydxaALwx0Dg
-----END CREV PACKAGE REVIEW-----
"""

const broken_id = """
-----BEGIN CREV PACKAGE REVIEW-----
version: -1
date: "2018-12-18T23:10:21.111854021-08:00"
from:
  id-type: crev
  id: FYlr8YoYGVvDwHQxqEIs89reKKDy-oWisoO0qXXEfHE
  url: 5
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

const bad_signature = """
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
4R2W5tU-avpBznmJYAl44H1lOYgETu3RSNhCDcB4GpqhJbSRkd-eqnUuhHgDUs77OlhUf7BSA0dydxaALwx0Dg
-----END CREV PACKAGE REVIEW-----
"""

@testset "Proof Stream" begin
    # Test that we can iterate through the right number of proofs
    count = 0
    for review in ProofStream(IOBuffer(review1))
        @test review isa Crev.Proof
        count += 1
    end
    @test count == 1
    count = 0
    for review in ProofStream(IOBuffer(review1^3))
        @test review isa Crev.Proof
        count += 1
    end
    @test count == 3

    for review in ProofStream(IOBuffer(malformed_yaml^2))
        @test review isa Crev.MalformedProof{YAML.ParserError}
    end
    for review in ProofStream(IOBuffer(broken_id^2))
        @test review isa Crev.MalformedProof{ErrorException}
    end
    for review in ProofStream(IOBuffer(bad_signature^2))
        @test review isa Crev.MalformedProof{ErrorException}
    end
end

const kp1 = Crev.Signing.KeyPair(
    "MsDfuccCJUs-ACAB-JF_jsPiNw8DDlbXKw91v20BQyQ",
    "fKqEyUdGBPpCkfajQUzN46c6kO5bgZqCJOoma_UstYEywN-5xwIlSz4AIAH4kX-Ow-I3DwMOVtcrD3W_bQFDJA")

@testset "Signing" begin
    kp = Crev.Signing.KeyPair()
    @test any(b-> b != 0x00, kp.pk.data)
    @test any(b-> b != 0x00, kp.sk.data)
    Base.shred!(kp.pk)
    @test all(b-> b === 0x00, kp.pk.data)
    finalize(kp.sk)
    @test all(b-> b === 0x00, kp.sk.data)
    @test Crev.Signing.base64encode(kp1.pk) == "MsDfuccCJUs-ACAB-JF_jsPiNw8DDlbXKw91v20BQyQ"
    @test Crev.Signing.sign("hello world", kp1.sk) ==
        "JCZUYUZQ7cJuPUX5zRFw_GAJ42_wrC0rUPyj_j0CtgHTobX6HfhPOgNN7o6i4T0lzQBJATr4yqK_2oGASi96Dw"
    @test Crev.Signing.verify(
        "JCZUYUZQ7cJuPUX5zRFw_GAJ42_wrC0rUPyj_j0CtgHTobX6HfhPOgNN7o6i4T0lzQBJATr4yqK_2oGASi96Dw",
        "hello world", kp1.pk)
end
