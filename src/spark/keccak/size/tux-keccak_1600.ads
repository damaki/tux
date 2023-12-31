--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces;

with Tux.Generic_Keccak;
with Tux.Types;
with Tux.Types.Conversions;

--  @summary
--  Keccak-f instance with 64-bit lanes (Keccak-f[1600])
package Tux.Keccak_1600 with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is
   package Keccak is new Tux.Generic_Keccak
     (Lane_Type     => Interfaces.Unsigned_64,
      Lane_Size_Log => 6,
      To_Lane       => Tux.Types.Conversions.To_U64_LE,
      To_Bytes      => Tux.Types.Conversions.To_Bytes_LE,
      Rotate_Left   => Interfaces.Rotate_Left);

   procedure Permute_24 (Ctx : in out Keccak.Context) with Inline;
   procedure Permute_12 (Ctx : in out Keccak.Context) with Inline;

end Tux.Keccak_1600;