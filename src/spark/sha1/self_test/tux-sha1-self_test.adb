--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

function Tux.SHA1.Self_Test return Boolean
is

   ----------------------------
   -- Test Vector Definition --
   ----------------------------

   --  The test data is represented as one message "part" that is processed
   --  one or more times into the SHA-1 computation. The overall message
   --  length is the part length multiplied by the number of parts.

   subtype Data_Range is Positive range 1 .. 56;

   type Test_Vector is record
      Data_Part   : Types.Byte_Array (Data_Range);
      Part_Length   : Data_Range;
      Num_Parts     : Natural range 0 .. 20_000;
      Expected_Hash : Byte_Array (1 .. SHA1_Hash_Length);
   end record;

   ------------------
   -- Test Vectors --
   ------------------

   --  These test vectors are from Appendix A of NIST FIPS 180-2

   Test_Vectors : constant array (1 .. 3) of Test_Vector :=
     ((Data_Part     => (16#61#, 16#62#, 16#63#, others => 0), --  "abc"
       Part_Length   => 3,
       Num_Parts     => 1,
       Expected_Hash =>
         (16#A9#, 16#99#, 16#3E#, 16#36#, 16#47#, 16#06#, 16#81#, 16#6A#,
          16#BA#, 16#3E#, 16#25#, 16#71#, 16#78#, 16#50#, 16#C2#, 16#6C#,
          16#9C#, 16#D0#, 16#D8#, 16#9D#)),

      (Data_Part      =>
           (
            --  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            16#61#, 16#62#, 16#63#, 16#64#, 16#62#, 16#63#, 16#64#, 16#65#,
            16#63#, 16#64#, 16#65#, 16#66#, 16#64#, 16#65#, 16#66#, 16#67#,
            16#65#, 16#66#, 16#67#, 16#68#, 16#66#, 16#67#, 16#68#, 16#69#,
            16#67#, 16#68#, 16#69#, 16#6A#, 16#68#, 16#69#, 16#6A#, 16#6B#,
            16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6A#, 16#6B#, 16#6C#, 16#6D#,
            16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6C#, 16#6D#, 16#6E#, 16#6F#,
            16#6D#, 16#6E#, 16#6F#, 16#70#, 16#6E#, 16#6F#, 16#70#, 16#71#
           ),
       Part_Length   => 56,
       Num_Parts     => 1,
       Expected_Hash =>
         (16#84#, 16#98#, 16#3E#, 16#44#, 16#1C#, 16#3B#, 16#D2#, 16#6E#,
          16#BA#, 16#AE#, 16#4A#, 16#A1#, 16#F9#, 16#51#, 16#29#, 16#E5#,
          16#E5#, 16#46#, 16#70#, 16#F1#)),

      (Data_Part     => (1 .. 50 => 16#61#, others => 0), --  "a" * 50
       Part_Length   => 50,
       Num_Parts     => 20_000, --  50 * 20,000 = 1,000,000 bytes total
       Expected_Hash =>
         (16#34#, 16#AA#, 16#97#, 16#3C#, 16#D4#, 16#C4#, 16#DA#, 16#A4#,
          16#F6#, 16#1E#, 16#EB#, 16#2B#, 16#DB#, 16#AD#, 16#27#, 16#31#,
          16#65#, 16#34#, 16#01#, 16#6F#)));

   Hash : Types.Byte_Array (1 .. SHA1_Hash_Length);

   Ctx : Context;

begin
   for Test of Test_Vectors loop
      Initialize (Ctx);

      for I in Positive range 1 .. Test.Num_Parts loop
         pragma Loop_Invariant (not Finished (Ctx));

         Update (Ctx, Test.Data_Part (1 .. Test.Part_Length));
      end loop;

      Finish (Ctx, Hash);

      if not Equal_Constant_Time (Hash, Test.Expected_Hash) then
         return False;
      end if;
   end loop;

   return True;
end Tux.SHA1.Self_Test;
