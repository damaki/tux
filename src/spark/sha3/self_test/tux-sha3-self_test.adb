--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types;

function Tux.SHA3.Self_Test return Boolean is

   ----------------------------
   -- Test Vector Definition --
   ----------------------------

   --  The test data is represented as one message "part" that is processed one
   --  or more times into the SHA-3 computation. The overall message length is
   --  the part length multiplied by the number of parts.

   subtype Data_Range is Positive range 1 .. 56;

   type Test_Vector is record
      Data_Part         : Types.Byte_Array (Data_Range);
      Part_Length       : Data_Range;
      Num_Parts         : Natural range 0 .. 20_000;
      Expected_Hash_224 : SHA3_224_Hash;
      Expected_Hash_256 : SHA3_256_Hash;
      Expected_Hash_384 : SHA3_384_Hash;
      Expected_Hash_512 : SHA3_512_Hash;
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

   --  These test vectors were obtained by running these inputs with the
   --  reference implementation from the SHA-3 authors in the
   --  eXtended Keccak Code Package (XKCP).

   Test_Vectors : constant array (1 .. 3) of Test_Vector :=
     ((Data_Part         => (16#61#, 16#62#, 16#63#, others => 0), --  "abc"
       Part_Length       => 3,
       Num_Parts         => 1,
       Expected_Hash_224 =>
         (16#E6#, 16#42#, 16#82#, 16#4C#, 16#3F#, 16#8C#, 16#F2#, 16#4A#,
          16#D0#, 16#92#, 16#34#, 16#EE#, 16#7D#, 16#3C#, 16#76#, 16#6F#,
          16#C9#, 16#A3#, 16#A5#, 16#16#, 16#8D#, 16#0C#, 16#94#, 16#AD#,
          16#73#, 16#B4#, 16#6F#, 16#DF#),
       Expected_Hash_256 =>
         (16#3A#, 16#98#, 16#5D#, 16#A7#, 16#4F#, 16#E2#, 16#25#, 16#B2#,
          16#04#, 16#5C#, 16#17#, 16#2D#, 16#6B#, 16#D3#, 16#90#, 16#BD#,
          16#85#, 16#5F#, 16#08#, 16#6E#, 16#3E#, 16#9D#, 16#52#, 16#5B#,
          16#46#, 16#BF#, 16#E2#, 16#45#, 16#11#, 16#43#, 16#15#, 16#32#),
       Expected_Hash_384 =>
         (16#EC#, 16#01#, 16#49#, 16#82#, 16#88#, 16#51#, 16#6F#, 16#C9#,
          16#26#, 16#45#, 16#9F#, 16#58#, 16#E2#, 16#C6#, 16#AD#, 16#8D#,
          16#F9#, 16#B4#, 16#73#, 16#CB#, 16#0F#, 16#C0#, 16#8C#, 16#25#,
          16#96#, 16#DA#, 16#7C#, 16#F0#, 16#E4#, 16#9B#, 16#E4#, 16#B2#,
          16#98#, 16#D8#, 16#8C#, 16#EA#, 16#92#, 16#7A#, 16#C7#, 16#F5#,
          16#39#, 16#F1#, 16#ED#, 16#F2#, 16#28#, 16#37#, 16#6D#, 16#25#),
       Expected_Hash_512 =>
         (16#B7#, 16#51#, 16#85#, 16#0B#, 16#1A#, 16#57#, 16#16#, 16#8A#,
          16#56#, 16#93#, 16#CD#, 16#92#, 16#4B#, 16#6B#, 16#09#, 16#6E#,
          16#08#, 16#F6#, 16#21#, 16#82#, 16#74#, 16#44#, 16#F7#, 16#0D#,
          16#88#, 16#4F#, 16#5D#, 16#02#, 16#40#, 16#D2#, 16#71#, 16#2E#,
          16#10#, 16#E1#, 16#16#, 16#E9#, 16#19#, 16#2A#, 16#F3#, 16#C9#,
          16#1A#, 16#7E#, 16#C5#, 16#76#, 16#47#, 16#E3#, 16#93#, 16#40#,
          16#57#, 16#34#, 16#0B#, 16#4C#, 16#F4#, 16#08#, 16#D5#, 16#A5#,
          16#65#, 16#92#, 16#F8#, 16#27#, 16#4E#, 16#EC#, 16#53#, 16#F0#)),

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
         (16#8A#, 16#24#, 16#10#, 16#8B#, 16#15#, 16#4A#, 16#DA#, 16#21#,
          16#C9#, 16#FD#, 16#55#, 16#74#, 16#49#, 16#44#, 16#79#, 16#BA#,
          16#5C#, 16#7E#, 16#7A#, 16#B7#, 16#6E#, 16#F2#, 16#64#, 16#EA#,
          16#D0#, 16#FC#, 16#CE#, 16#33#),
       Expected_Hash_256   =>
         (16#41#, 16#C0#, 16#DB#, 16#A2#, 16#A9#, 16#D6#, 16#24#, 16#08#,
          16#49#, 16#10#, 16#03#, 16#76#, 16#A8#, 16#23#, 16#5E#, 16#2C#,
          16#82#, 16#E1#, 16#B9#, 16#99#, 16#8A#, 16#99#, 16#9E#, 16#21#,
          16#DB#, 16#32#, 16#DD#, 16#97#, 16#49#, 16#6D#, 16#33#, 16#76#),
       Expected_Hash_384   =>
         (16#99#, 16#1C#, 16#66#, 16#57#, 16#55#, 16#EB#, 16#3A#, 16#4B#,
          16#6B#, 16#BD#, 16#FB#, 16#75#, 16#C7#, 16#8A#, 16#49#, 16#2E#,
          16#8C#, 16#56#, 16#A2#, 16#2C#, 16#5C#, 16#4D#, 16#7E#, 16#42#,
          16#9B#, 16#FD#, 16#BC#, 16#32#, 16#B9#, 16#D4#, 16#AD#, 16#5A#,
          16#A0#, 16#4A#, 16#1F#, 16#07#, 16#6E#, 16#62#, 16#FE#, 16#A1#,
          16#9E#, 16#EF#, 16#51#, 16#AC#, 16#D0#, 16#65#, 16#7C#, 16#22#),
       Expected_Hash_512   =>
         (16#04#, 16#A3#, 16#71#, 16#E8#, 16#4E#, 16#CF#, 16#B5#, 16#B8#,
          16#B7#, 16#7C#, 16#B4#, 16#86#, 16#10#, 16#FC#, 16#A8#, 16#18#,
          16#2D#, 16#D4#, 16#57#, 16#CE#, 16#6F#, 16#32#, 16#6A#, 16#0F#,
          16#D3#, 16#D7#, 16#EC#, 16#2F#, 16#1E#, 16#91#, 16#63#, 16#6D#,
          16#EE#, 16#69#, 16#1F#, 16#BE#, 16#0C#, 16#98#, 16#53#, 16#02#,
          16#BA#, 16#1B#, 16#0D#, 16#8D#, 16#C7#, 16#8C#, 16#08#, 16#63#,
          16#46#, 16#B5#, 16#33#, 16#B4#, 16#9C#, 16#03#, 16#0D#, 16#99#,
          16#A2#, 16#7D#, 16#AF#, 16#11#, 16#39#, 16#D6#, 16#E7#, 16#5E#)),

      (Data_Part     => (1 .. 50 => 16#61#, others => 0), --  "a" * 50
       Part_Length   => 50,
       Num_Parts     => 20_000, --  50 * 20,000 = 1,000,000 bytes total
       Expected_Hash_224   =>
         (16#D6#, 16#93#, 16#35#, 16#B9#, 16#33#, 16#25#, 16#19#, 16#2E#,
          16#51#, 16#6A#, 16#91#, 16#2E#, 16#6D#, 16#19#, 16#A1#, 16#5C#,
          16#B5#, 16#1C#, 16#6E#, 16#D5#, 16#C1#, 16#52#, 16#43#, 16#E7#,
          16#A7#, 16#FD#, 16#65#, 16#3C#),
       Expected_Hash_256   =>
         (16#5C#, 16#88#, 16#75#, 16#AE#, 16#47#, 16#4A#, 16#36#, 16#34#,
          16#BA#, 16#4F#, 16#D5#, 16#5E#, 16#C8#, 16#5B#, 16#FF#, 16#D6#,
          16#61#, 16#F3#, 16#2A#, 16#CA#, 16#75#, 16#C6#, 16#D6#, 16#99#,
          16#D0#, 16#CD#, 16#CB#, 16#6C#, 16#11#, 16#58#, 16#91#, 16#C1#),
       Expected_Hash_384   =>
         (16#EE#, 16#E9#, 16#E2#, 16#4D#, 16#78#, 16#C1#, 16#85#, 16#53#,
          16#37#, 16#98#, 16#34#, 16#51#, 16#DF#, 16#97#, 16#C8#, 16#AD#,
          16#9E#, 16#ED#, 16#F2#, 16#56#, 16#C6#, 16#33#, 16#4F#, 16#8E#,
          16#94#, 16#8D#, 16#25#, 16#2D#, 16#5E#, 16#0E#, 16#76#, 16#84#,
          16#7A#, 16#A0#, 16#77#, 16#4D#, 16#DB#, 16#90#, 16#A8#, 16#42#,
          16#19#, 16#0D#, 16#2C#, 16#55#, 16#8B#, 16#4B#, 16#83#, 16#40#),
       Expected_Hash_512   =>
         (16#3C#, 16#3A#, 16#87#, 16#6D#, 16#A1#, 16#40#, 16#34#, 16#AB#,
          16#60#, 16#62#, 16#7C#, 16#07#, 16#7B#, 16#B9#, 16#8F#, 16#7E#,
          16#12#, 16#0A#, 16#2A#, 16#53#, 16#70#, 16#21#, 16#2D#, 16#FF#,
          16#B3#, 16#38#, 16#5A#, 16#18#, 16#D4#, 16#F3#, 16#88#, 16#59#,
          16#ED#, 16#31#, 16#1D#, 16#0A#, 16#9D#, 16#51#, 16#41#, 16#CE#,
          16#9C#, 16#C5#, 16#C6#, 16#6E#, 16#E6#, 16#89#, 16#B2#, 16#66#,
          16#A8#, 16#AA#, 16#18#, 16#AC#, 16#E8#, 16#28#, 16#2A#, 16#0E#,
          16#0D#, 16#B5#, 16#96#, 16#C9#, 16#0B#, 16#0A#, 16#7B#, 16#87#)));

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

      Result := Run_Test_Vector (Test, SHA3_224, Test.Expected_Hash_224);

      if not Result then
         return False;
      end if;

      Result := Run_Test_Vector (Test, SHA3_256, Test.Expected_Hash_256);

      if not Result then
         return False;
      end if;

      Result := Run_Test_Vector (Test, SHA3_384, Test.Expected_Hash_384);

      if not Result then
         return False;
      end if;

      Result := Run_Test_Vector (Test, SHA3_512, Test.Expected_Hash_512);

      if not Result then
         return False;
      end if;

   end loop;

   return True;
end Tux.SHA3.Self_Test;
