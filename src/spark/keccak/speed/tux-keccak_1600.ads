--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
pragma SPARK_Mode (On);

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

   --  This is the version optimized for speed. Generic_Permute is instantiated
   --  with a static number of rounds to enable optimizations based on the
   --  specific number of rounds.

   procedure Permute_24 is new Keccak.Generic_Permute (Num_Rounds => 24);
   procedure Permute_12 is new Keccak.Generic_Permute (Num_Rounds => 12);

end Tux.Keccak_1600;