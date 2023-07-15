--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types;

function Tux.SHA256.Self_Test return Boolean is

   ----------------------------
   -- Test Vector Definition --
   ----------------------------

   --  The test data is represented as one message "part" that is processed one
   --  or more times into the SHA-256/224 computation. The overall message
   --  length is the part length multiplied by the number of parts.

   subtype Data_Range is Positive range 1 .. 56;

   type Test_Vector is record
      Data_Part         : Types.Byte_Array (Data_Range);
      Part_Length       : Data_Range;
      Num_Parts         : Natural range 0 .. 20_000;
      Expected_Hash_224 : SHA224_Hash;
      Expected_Hash_256 : SHA256_Hash;
   end record;

   function Run_Test_Vector
     (Test          : Test_Vector;
      Algorithm     : Algorithm_Kind;
      Expected_Hash : Types.Byte_Array)
      return Boolean
   with
     Pre => Expected_Hash'Length = Hash_Length (Algorithm);
   --  Run a single test vector with the specified algorithm

   ------------------
   -- Test Vectors --
   ------------------

   --  These test vectors are from Appendix B of NIST FIPS 180-2

   Test_Vectors : constant array (1 .. 3) of Test_Vector :=
     ((Data_Part         => (16#61#, 16#62#, 16#63#, others => 0), --  "abc"
       Part_Length       => 3,
       Num_Parts         => 1,
       Expected_Hash_224 =>
         (16#23#, 16#09#, 16#7D#, 16#22#, 16#34#, 16#05#, 16#D8#, 16#22#,
          16#86#, 16#42#, 16#A4#, 16#77#, 16#BD#, 16#A2#, 16#55#, 16#B3#,
          16#2A#, 16#AD#, 16#BC#, 16#E4#, 16#BD#, 16#A0#, 16#B3#, 16#F7#,
          16#E3#, 16#6C#, 16#9D#, 16#A7#),
       Expected_Hash_256 =>
         (16#BA#, 16#78#, 16#16#, 16#BF#, 16#8F#, 16#01#, 16#CF#, 16#EA#,
          16#41#, 16#41#, 16#40#, 16#DE#, 16#5D#, 16#AE#, 16#22#, 16#23#,
          16#B0#, 16#03#, 16#61#, 16#A3#, 16#96#, 16#17#, 16#7A#, 16#9C#,
          16#B4#, 16#10#, 16#FF#, 16#61#, 16#F2#, 16#00#, 16#15#, 16#AD#)),

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
       Part_Length         => 56,
       Num_Parts           => 1,
       Expected_Hash_224   =>
         (16#75#, 16#38#, 16#8B#, 16#16#, 16#51#, 16#27#, 16#76#, 16#CC#,
          16#5D#, 16#BA#, 16#5D#, 16#A1#, 16#FD#, 16#89#, 16#01#, 16#50#,
          16#B0#, 16#C6#, 16#45#, 16#5C#, 16#B4#, 16#F5#, 16#8B#, 16#19#,
          16#52#, 16#52#, 16#25#, 16#25#),
       Expected_Hash_256   =>
         (16#24#, 16#8D#, 16#6A#, 16#61#, 16#D2#, 16#06#, 16#38#, 16#B8#,
          16#E5#, 16#C0#, 16#26#, 16#93#, 16#0C#, 16#3E#, 16#60#, 16#39#,
          16#A3#, 16#3C#, 16#E4#, 16#59#, 16#64#, 16#FF#, 16#21#, 16#67#,
          16#F6#, 16#EC#, 16#ED#, 16#D4#, 16#19#, 16#DB#, 16#06#, 16#C1#)),

      (Data_Part     => (1 .. 50 => 16#61#, others => 0), --  "a" * 50
       Part_Length   => 50,
       Num_Parts     => 20_000, --  50 * 20,000 = 1,000,000 bytes total
       Expected_Hash_224   =>
         (16#20#, 16#79#, 16#46#, 16#55#, 16#98#, 16#0C#, 16#91#, 16#D8#,
          16#BB#, 16#B4#, 16#C1#, 16#EA#, 16#97#, 16#61#, 16#8A#, 16#4B#,
          16#F0#, 16#3F#, 16#42#, 16#58#, 16#19#, 16#48#, 16#B2#, 16#EE#,
          16#4E#, 16#E7#, 16#AD#, 16#67#),
       Expected_Hash_256   =>
         (16#CD#, 16#C7#, 16#6E#, 16#5C#, 16#99#, 16#14#, 16#FB#, 16#92#,
          16#81#, 16#A1#, 16#C7#, 16#E2#, 16#84#, 16#D7#, 16#3E#, 16#67#,
          16#F1#, 16#80#, 16#9A#, 16#48#, 16#A4#, 16#97#, 16#20#, 16#0E#,
          16#04#, 16#6D#, 16#39#, 16#CC#, 16#C7#, 16#11#, 16#2C#, 16#D0#)));

   ---------------------
   -- Run_Test_Vector --
   ---------------------

   function Run_Test_Vector
     (Test          : Test_Vector;
      Algorithm     : Algorithm_Kind;
      Expected_Hash : Types.Byte_Array)
      return Boolean
   is
      HLen : constant Hash_Length_Number := Hash_Length (Algorithm);
      Hash : Types.Byte_Array (1 .. HLen);
      Ctx  : Context (Algorithm);

   begin
      Initialize (Ctx);

      for I in Positive range 1 .. Test.Num_Parts loop
         pragma Loop_Invariant (not Finished (Ctx));

         Update (Ctx, Test.Data_Part (1 .. Test.Part_Length));
      end loop;

      Finish (Ctx, Hash);

      pragma Unreferenced (Ctx);

      return Equal_Constant_Time (Hash, Expected_Hash);
   end Run_Test_Vector;

   Result : Boolean;

begin
   for Test of Test_Vectors loop

      Result := Run_Test_Vector (Test, SHA224, Test.Expected_Hash_224);

      if not Result then
         return False;
      end if;

      Result := Run_Test_Vector (Test, SHA256, Test.Expected_Hash_256);

      if not Result then
         return False;
      end if;

   end loop;

   return True;
end Tux.SHA256.Self_Test;
