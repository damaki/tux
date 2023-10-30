--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
pragma SPARK_Mode;

with Tux.Types;

function Tux.SHA512.Self_Test return Boolean is

   ----------------------------
   -- Test Vector Definition --
   ----------------------------

   --  The test data is represented as one message "part" that is processed one
   --  or more times into the SHA-512/384 computation. The overall message
   --  length is the part length multiplied by the number of parts.

   subtype Data_Range is Positive range 1 .. 112;

   type Test_Vector is record
      Data_Part             : Types.Byte_Array (Data_Range);
      Part_Length           : Data_Range;
      Num_Parts             : Natural range 0 .. 20_000;
      Expected_Hash_384     : SHA384_Hash;
      Expected_Hash_512     : SHA512_Hash;
      Expected_Hash_512_224 : SHA512_224_Hash;
      Expected_Hash_512_256 : SHA512_256_Hash;
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

   --  These test vectors are from NIST's Examples with Intermediate Values

   Test_Vectors : constant array (1 .. 2) of Test_Vector :=
     ((Data_Part     => (16#61#, 16#62#, 16#63#, others => 0), --  "abc"
       Part_Length   => 3,
       Num_Parts     => 1,
       Expected_Hash_384   =>
         (16#CB#, 16#00#, 16#75#, 16#3F#, 16#45#, 16#A3#, 16#5E#, 16#8B#,
          16#B5#, 16#A0#, 16#3D#, 16#69#, 16#9A#, 16#C6#, 16#50#, 16#07#,
          16#27#, 16#2C#, 16#32#, 16#AB#, 16#0E#, 16#DE#, 16#D1#, 16#63#,
          16#1A#, 16#8B#, 16#60#, 16#5A#, 16#43#, 16#FF#, 16#5B#, 16#ED#,
          16#80#, 16#86#, 16#07#, 16#2B#, 16#A1#, 16#E7#, 16#CC#, 16#23#,
          16#58#, 16#BA#, 16#EC#, 16#A1#, 16#34#, 16#C8#, 16#25#, 16#A7#),
       Expected_Hash_512   =>
         (16#DD#, 16#AF#, 16#35#, 16#A1#, 16#93#, 16#61#, 16#7A#, 16#BA#,
          16#CC#, 16#41#, 16#73#, 16#49#, 16#AE#, 16#20#, 16#41#, 16#31#,
          16#12#, 16#E6#, 16#FA#, 16#4E#, 16#89#, 16#A9#, 16#7E#, 16#A2#,
          16#0A#, 16#9E#, 16#EE#, 16#E6#, 16#4B#, 16#55#, 16#D3#, 16#9A#,
          16#21#, 16#92#, 16#99#, 16#2A#, 16#27#, 16#4F#, 16#C1#, 16#A8#,
          16#36#, 16#BA#, 16#3C#, 16#23#, 16#A3#, 16#FE#, 16#EB#, 16#BD#,
          16#45#, 16#4D#, 16#44#, 16#23#, 16#64#, 16#3C#, 16#E8#, 16#0E#,
          16#2A#, 16#9A#, 16#C9#, 16#4F#, 16#A5#, 16#4C#, 16#A4#, 16#9F#),
       Expected_Hash_512_224 =>
         (16#46#, 16#34#, 16#27#, 16#0F#, 16#70#, 16#7B#, 16#6A#, 16#54#,
          16#DA#, 16#AE#, 16#75#, 16#30#, 16#46#, 16#08#, 16#42#, 16#E2#,
          16#0E#, 16#37#, 16#ED#, 16#26#, 16#5C#, 16#EE#, 16#E9#, 16#A4#,
          16#3E#, 16#89#, 16#24#, 16#AA#),
       Expected_Hash_512_256 =>
         (16#53#, 16#04#, 16#8E#, 16#26#, 16#81#, 16#94#, 16#1E#, 16#F9#,
          16#9B#, 16#2E#, 16#29#, 16#B7#, 16#6B#, 16#4C#, 16#7D#, 16#AB#,
          16#E4#, 16#C2#, 16#D0#, 16#C6#, 16#34#, 16#FC#, 16#6D#, 16#46#,
          16#E0#, 16#E2#, 16#F1#, 16#31#, 16#07#, 16#E7#, 16#AF#, 16#23#)),

      (Data_Part      =>
           (
            --  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" &
            --  "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            16#61#, 16#62#, 16#63#, 16#64#, 16#65#, 16#66#, 16#67#, 16#68#,
            16#62#, 16#63#, 16#64#, 16#65#, 16#66#, 16#67#, 16#68#, 16#69#,
            16#63#, 16#64#, 16#65#, 16#66#, 16#67#, 16#68#, 16#69#, 16#6A#,
            16#64#, 16#65#, 16#66#, 16#67#, 16#68#, 16#69#, 16#6A#, 16#6B#,
            16#65#, 16#66#, 16#67#, 16#68#, 16#69#, 16#6A#, 16#6B#, 16#6C#,
            16#66#, 16#67#, 16#68#, 16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6D#,
            16#67#, 16#68#, 16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6D#, 16#6E#,
            16#68#, 16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6F#,
            16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6F#, 16#70#,
            16#6A#, 16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6F#, 16#70#, 16#71#,
            16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6F#, 16#70#, 16#71#, 16#72#,
            16#6C#, 16#6D#, 16#6E#, 16#6F#, 16#70#, 16#71#, 16#72#, 16#73#,
            16#6D#, 16#6E#, 16#6F#, 16#70#, 16#71#, 16#72#, 16#73#, 16#74#,
            16#6E#, 16#6F#, 16#70#, 16#71#, 16#72#, 16#73#, 16#74#, 16#75#
           ),
       Part_Length   => 112,
       Num_Parts     => 1,
       Expected_Hash_384   =>
         (16#09#, 16#33#, 16#0C#, 16#33#, 16#F7#, 16#11#, 16#47#, 16#E8#,
          16#3D#, 16#19#, 16#2F#, 16#C7#, 16#82#, 16#CD#, 16#1B#, 16#47#,
          16#53#, 16#11#, 16#1B#, 16#17#, 16#3B#, 16#3B#, 16#05#, 16#D2#,
          16#2F#, 16#A0#, 16#80#, 16#86#, 16#E3#, 16#B0#, 16#F7#, 16#12#,
          16#FC#, 16#C7#, 16#C7#, 16#1A#, 16#55#, 16#7E#, 16#2D#, 16#B9#,
          16#66#, 16#C3#, 16#E9#, 16#FA#, 16#91#, 16#74#, 16#60#, 16#39#),
       Expected_Hash_512   =>
         (16#8E#, 16#95#, 16#9B#, 16#75#, 16#DA#, 16#E3#, 16#13#, 16#DA#,
          16#8C#, 16#F4#, 16#F7#, 16#28#, 16#14#, 16#FC#, 16#14#, 16#3F#,
          16#8F#, 16#77#, 16#79#, 16#C6#, 16#EB#, 16#9F#, 16#7F#, 16#A1#,
          16#72#, 16#99#, 16#AE#, 16#AD#, 16#B6#, 16#88#, 16#90#, 16#18#,
          16#50#, 16#1D#, 16#28#, 16#9E#, 16#49#, 16#00#, 16#F7#, 16#E4#,
          16#33#, 16#1B#, 16#99#, 16#DE#, 16#C4#, 16#B5#, 16#43#, 16#3A#,
          16#C7#, 16#D3#, 16#29#, 16#EE#, 16#B6#, 16#DD#, 16#26#, 16#54#,
          16#5E#, 16#96#, 16#E5#, 16#5B#, 16#87#, 16#4B#, 16#E9#, 16#09#),
       Expected_Hash_512_224 =>
         (16#23#, 16#FE#, 16#C5#, 16#BB#, 16#94#, 16#D6#, 16#0B#, 16#23#,
          16#30#, 16#81#, 16#92#, 16#64#, 16#0B#, 16#0C#, 16#45#, 16#33#,
          16#35#, 16#D6#, 16#64#, 16#73#, 16#4F#, 16#E4#, 16#0E#, 16#72#,
          16#68#, 16#67#, 16#4A#, 16#F9#),
       Expected_Hash_512_256 =>
         (16#39#, 16#28#, 16#E1#, 16#84#, 16#FB#, 16#86#, 16#90#, 16#F8#,
          16#40#, 16#DA#, 16#39#, 16#88#, 16#12#, 16#1D#, 16#31#, 16#BE#,
          16#65#, 16#CB#, 16#9D#, 16#3E#, 16#F8#, 16#3E#, 16#E6#, 16#14#,
          16#6F#, 16#EA#, 16#C8#, 16#61#, 16#E1#, 16#9B#, 16#56#, 16#3A#)));

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

      Result := Run_Test_Vector (Test, SHA384, Test.Expected_Hash_384);

      if not Result then
         return False;
      end if;

      Result := Run_Test_Vector (Test, SHA512, Test.Expected_Hash_512);

      if not Result then
         return False;
      end if;

      Result := Run_Test_Vector (Test, SHA512_224, Test.Expected_Hash_512_224);

      if not Result then
         return False;
      end if;

      Result := Run_Test_Vector (Test, SHA512_256, Test.Expected_Hash_512_256);

      if not Result then
         return False;
      end if;

   end loop;

   return True;
end Tux.SHA512.Self_Test;
