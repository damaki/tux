--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Sanitization;

--  This is a "lane complemented" implementation of Keccak-f.
--  It reduces the number of NOT operations to 1 per plane by storing
--  the complement of certain lanes.

package body Tux.Generic_Keccak is

   procedure Sanitize_Context is new Tux.Sanitization.Generic_Sanitize
     (Element_Type   => Context,
      Sanitize_Value => (0 => (4         => Lane_Type'Last,
                               others    => 0),
                         1 => (0         => Lane_Type'Last,
                               others    => 0),
                         2 => (0 | 2 | 3 => Lane_Type'Last,
                               others    => 0),
                         3 => (1         => Lane_Type'Last,
                               others    => 0),
                         4 => (others    => 0)));
   --  Resets the context to its initial state.
   --
   --  Note that this lane-complementing implementation requires some rounds
   --  to be initialized to their complemented state.

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) renames Sanitize_Context;

   ----------------------------
   -- XOR_Bytes_Into_Context --
   ----------------------------

   procedure XOR_Bytes_Into_Context
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
      Offset : Byte_Count := 0;
      Pos    : Index_Number;
      Lane   : Lane_Type;

   begin
      --  Process full lanes

      Outer_Loop :
      for Y in Y_Coord loop
         pragma Loop_Invariant (Offset mod Lane_Size_Bytes = 0);
         pragma Loop_Invariant (Offset <= Data'Length);
         pragma Loop_Invariant (Offset = Byte_Count (Y) * Lane_Size_Bytes * 5);

         for X in X_Coord loop
            pragma Loop_Invariant (Offset mod Lane_Size_Bytes = 0);
            pragma Loop_Invariant (Offset <= Data'Length);
            pragma Loop_Invariant
              (Offset = (Byte_Count (Y) * Lane_Size_Bytes * 5) +
                        (Byte_Count (X) * Lane_Size_Bytes));

            exit Outer_Loop when Offset >= Data'Length;

            Pos  := Data'First + Offset;
            Lane := To_Lane (Data (Pos .. Pos + Lane_Size_Bytes - 1));

            Ctx (X, Y) := Ctx (X, Y) xor Lane;

            Offset := Offset + Lane_Size_Bytes;
         end loop;
      end loop Outer_Loop;
   end XOR_Bytes_Into_Context;

   -------------------
   -- Extract_Bytes --
   -------------------

   procedure Extract_Bytes
     (Ctx  :     Context;
      Data : out Byte_Array)
   is
      Complement_Mask : constant Context :=
        (0 => (4         => Lane_Type'Last,
               others    => 0),
         1 => (0         => Lane_Type'Last,
               others    => 0),
         2 => (0 | 2 | 3 => Lane_Type'Last,
               others    => 0),
         3 => (1         => Lane_Type'Last,
               others    => 0),
         4 => (others    => 0));

      Offset : Byte_Count := 0;
      Pos    : Index_Number;

   begin
      --  Process full lanes

      Outer_Loop :
      for Y in Y_Coord loop
         pragma Loop_Invariant (Offset mod Lane_Size_Bytes = 0);
         pragma Loop_Invariant (Offset = Byte_Count (Y) * Lane_Size_Bytes * 5);
         pragma Loop_Invariant (Offset <= Data'Length);
         pragma Loop_Invariant
           (Data (Data'First .. Data'First + Offset - 1)'Initialized);

         for X in X_Coord loop
            pragma Loop_Invariant (Offset mod Lane_Size_Bytes = 0);
            pragma Loop_Invariant
              (Offset = (Byte_Count (Y) * Lane_Size_Bytes * 5) +
                        (Byte_Count (X) * Lane_Size_Bytes));
            pragma Loop_Invariant (Offset <= Data'Length);
            pragma Loop_Invariant
              (Data (Data'First .. Data'First + Offset - 1)'Initialized);

            exit Outer_Loop when Offset >= Data'Length;

            Pos  := Data'First + Offset;

            To_Bytes (Ctx (X, Y) xor Complement_Mask (X, Y),
                      Data (Pos .. Pos + Lane_Size_Bytes - 1));

            Offset := Offset + Lane_Size_Bytes;
         end loop;
      end loop Outer_Loop;
   end Extract_Bytes;

   -------------
   -- Permute --
   -------------

   procedure Permute
     (Ctx        : in out Context;
      Num_Rounds :        Round_Count)
   is
      type Round_Index is new Natural range 0 .. 23;

      Max_Rounds : constant Positive := 12 + (Lane_Size_Log * 2);

      First_Round : constant Round_Index := Round_Index (Max_Rounds - 1)
                                          - Round_Index (Num_Rounds - 1);

      type Round_Constants is array (Round_Index) of Interfaces.Unsigned_64;

      RC : constant Round_Constants :=
        (
         16#0000_0000_0000_0001#,
         16#0000_0000_0000_8082#,
         16#8000_0000_0000_808A#,
         16#8000_0000_8000_8000#,
         16#0000_0000_0000_808B#,
         16#0000_0000_8000_0001#,
         16#8000_0000_8000_8081#,
         16#8000_0000_0000_8009#,
         16#0000_0000_0000_008A#,
         16#0000_0000_0000_0088#,
         16#0000_0000_8000_8009#,
         16#0000_0000_8000_000A#,
         16#0000_0000_8000_808B#,
         16#8000_0000_0000_008B#,
         16#8000_0000_0000_8089#,
         16#8000_0000_0000_8003#,
         16#8000_0000_0000_8002#,
         16#8000_0000_0000_0080#,
         16#0000_0000_0000_800A#,
         16#8000_0000_8000_000A#,
         16#8000_0000_8000_8081#,
         16#8000_0000_0000_8080#,
         16#0000_0000_8000_0001#,
         16#8000_0000_8000_8008#
        );

      Aba, Abe, Abi, Abo, Abu : Lane_Type;
      Aga, Age, Agi, Ago, Agu : Lane_Type;
      Aka, Ake, Aki, Ako, Aku : Lane_Type;
      Ama, Ame, Ami, Amo, Amu : Lane_Type;
      Asa, Ase, Asi, Aso, Asu : Lane_Type;
      Ca, Ce, Ci, Co, Cu      : Lane_Type;
      Eba, Ebe, Ebi, Ebo, Ebu : Lane_Type;
      Ega, Ege, Egi, Ego, Egu : Lane_Type;
      Eka, Eke, Eki, Eko, Eku : Lane_Type;
      Ema, Eme, Emi, Emo, Emu : Lane_Type;
      Esa, Ese, Esi, Eso, Esu : Lane_Type;

      procedure Copy_From_State
        with Inline,
        Global => (Input  => Ctx,
                   Output => (Aba, Abe, Abi, Abo, Abu,
                              Aga, Age, Agi, Ago, Agu,
                              Aka, Ake, Aki, Ako, Aku,
                              Ama, Ame, Ami, Amo, Amu,
                              Asa, Ase, Asi, Aso, Asu));

      procedure Copy_To_State_From_A
        with Inline,
        Global => (Input  => (Aba, Abe, Abi, Abo, Abu,
                              Aga, Age, Agi, Ago, Agu,
                              Aka, Ake, Aki, Ako, Aku,
                              Ama, Ame, Ami, Amo, Amu,
                              Asa, Ase, Asi, Aso, Asu),
                   Output => Ctx);

      procedure Prepare_Theta
        with Inline,
        Global => (Input  => (Aba, Abe, Abi, Abo, Abu,
                              Aga, Age, Agi, Ago, Agu,
                              Aka, Ake, Aki, Ako, Aku,
                              Ama, Ame, Ami, Amo, Amu,
                              Asa, Ase, Asi, Aso, Asu),
                   Output => (Ca, Ce, Ci, Co, Cu));

      procedure Theta_Rho_Pi_Chi_Iota_Prepare_Theta_AtoE (RI : Round_Index)
        with Inline,
        Global => (Input => (Aba, Abe, Abi, Abo, Abu,
                             Aga, Age, Agi, Ago, Agu,
                             Aka, Ake, Aki, Ako, Aku,
                             Ama, Ame, Ami, Amo, Amu,
                             Asa, Ase, Asi, Aso, Asu),
                   In_Out => (Ca, Ce, Ci, Co, Cu),
                   Output => (Eba, Ebe, Ebi, Ebo, Ebu,
                              Ega, Ege, Egi, Ego, Egu,
                              Eka, Eke, Eki, Eko, Eku,
                              Ema, Eme, Emi, Emo, Emu,
                              Esa, Ese, Esi, Eso, Esu));

      procedure Theta_Rho_Pi_Chi_Iota_Prepare_Theta_EtoA (RI : Round_Index)
        with Inline,
        Global => (Input => (Eba, Ebe, Ebi, Ebo, Ebu,
                             Ega, Ege, Egi, Ego, Egu,
                             Eka, Eke, Eki, Eko, Eku,
                             Ema, Eme, Emi, Emo, Emu,
                             Esa, Ese, Esi, Eso, Esu),
                   In_Out => (Ca, Ce, Ci, Co, Cu),
                   Output => (Aba, Abe, Abi, Abo, Abu,
                              Aga, Age, Agi, Ago, Agu,
                              Aka, Ake, Aki, Ako, Aku,
                              Ama, Ame, Ami, Amo, Amu,
                              Asa, Ase, Asi, Aso, Asu));

      procedure Copy_From_State
      is
      begin
         Aba := Ctx (0, 0);
         Abe := Ctx (1, 0);
         Abi := Ctx (2, 0);
         Abo := Ctx (3, 0);
         Abu := Ctx (4, 0);
         Aga := Ctx (0, 1);
         Age := Ctx (1, 1);
         Agi := Ctx (2, 1);
         Ago := Ctx (3, 1);
         Agu := Ctx (4, 1);
         Aka := Ctx (0, 2);
         Ake := Ctx (1, 2);
         Aki := Ctx (2, 2);
         Ako := Ctx (3, 2);
         Aku := Ctx (4, 2);
         Ama := Ctx (0, 3);
         Ame := Ctx (1, 3);
         Ami := Ctx (2, 3);
         Amo := Ctx (3, 3);
         Amu := Ctx (4, 3);
         Asa := Ctx (0, 4);
         Ase := Ctx (1, 4);
         Asi := Ctx (2, 4);
         Aso := Ctx (3, 4);
         Asu := Ctx (4, 4);
      end Copy_From_State;

      procedure Copy_To_State_From_A
      is
      begin
         Ctx := (0 => (0 => Aba,
                       1 => Aga,
                       2 => Aka,
                       3 => Ama,
                       4 => Asa),
                 1 => (0 => Abe,
                       1 => Age,
                       2 => Ake,
                       3 => Ame,
                       4 => Ase),
                 2 => (0 => Abi,
                       1 => Agi,
                       2 => Aki,
                       3 => Ami,
                       4 => Asi),
                 3 => (0 => Abo,
                       1 => Ago,
                       2 => Ako,
                       3 => Amo,
                       4 => Aso),
                 4 => (0 => Abu,
                       1 => Agu,
                       2 => Aku,
                       3 => Amu,
                       4 => Asu)
                );
      end Copy_To_State_From_A;

      procedure Prepare_Theta
      is
      begin
         Ca := Aba xor Aga xor Aka xor Ama xor Asa;
         Ce := Abe xor Age xor Ake xor Ame xor Ase;
         Ci := Abi xor Agi xor Aki xor Ami xor Asi;
         Co := Abo xor Ago xor Ako xor Amo xor Aso;
         Cu := Abu xor Agu xor Aku xor Amu xor Asu;
      end Prepare_Theta;

      procedure Theta_Rho_Pi_Chi_Iota_Prepare_Theta_AtoE (RI : Round_Index)
      is
         Da, De, Di, D0, Du : Lane_Type;

         Bba, Bbe, Bbi, Bbo, Bbu : Lane_Type;
         Bga, Bge, Bgi, Bgo, Bgu : Lane_Type;
         Bka, Bke, Bki, Bko, Bku : Lane_Type;
         Bma, Bme, Bmi, Bmo, Bmu : Lane_Type;
         Bsa, Bse, Bsi, Bso, Bsu : Lane_Type;

      begin
         Da  := Cu xor Rotate_Left (Ce, 1);
         De  := Ca xor Rotate_Left (Ci, 1);
         Di  := Ce xor Rotate_Left (Co, 1);
         D0  := Ci xor Rotate_Left (Cu, 1);
         Du  := Co xor Rotate_Left (Ca, 1);

         Bba := Aba xor Da;
         Bbe := Rotate_Left (Age xor De, 300 mod Lane_Type'Size);
         Bbi := Rotate_Left (Aki xor Di, 171 mod Lane_Type'Size);
         Bbo := Rotate_Left (Amo xor D0, 21 mod Lane_Type'Size);
         Bbu := Rotate_Left (Asu xor Du, 78 mod Lane_Type'Size);
         Eba := Bba xor (Bbe or Bbi);
         Eba := Eba xor Lane_Type (RC (RI) and (2**Lane_Type'Size - 1));
         Ca  := Eba;
         Ebe := Bbe xor ((not Bbi) or Bbo);
         Ce  := Ebe;
         Ebi := Bbi xor (Bbo and Bbu);
         Ci  := Ebi;
         Ebo := Bbo xor (Bbu or Bba);
         Co  := Ebo;
         Ebu := Bbu xor (Bba and Bbe);
         Cu  := Ebu;

         Bga := Rotate_Left (Abo xor D0, 28 mod Lane_Type'Size);
         Bge := Rotate_Left (Agu xor Du, 276 mod Lane_Type'Size);
         Bgi := Rotate_Left (Aka xor Da, 3 mod Lane_Type'Size);
         Bgo := Rotate_Left (Ame xor De, 45 mod Lane_Type'Size);
         Bgu := Rotate_Left (Asi xor Di, 253 mod Lane_Type'Size);
         Ega := Bga xor (Bge or Bgi);
         Ca  := Ca xor Ega;
         Ege := Bge xor (Bgi and Bgo);
         Ce  := Ce xor Ege;
         Egi := Bgi xor (Bgo or (not Bgu));
         Ci  := Ci xor Egi;
         Ego := Bgo xor (Bgu or Bga);
         Co  := Co xor Ego;
         Egu := Bgu xor (Bga and Bge);
         Cu  := Cu xor Egu;

         Bka := Rotate_Left (Abe xor De, 1 mod Lane_Type'Size);
         Bke := Rotate_Left (Agi xor Di, 6 mod Lane_Type'Size);
         Bki := Rotate_Left (Ako xor D0, 153 mod Lane_Type'Size);
         Bko := Rotate_Left (Amu xor Du, 136 mod Lane_Type'Size);
         Bku := Rotate_Left (Asa xor Da, 210 mod Lane_Type'Size);
         Eka := Bka xor (Bke or Bki);
         Ca  := Ca xor Eka;
         Eke := Bke xor (Bki and Bko);
         Ce  := Ce xor Eke;
         Eki := Bki xor ((not Bko) and Bku);
         Ci  := Ci xor Eki;
         Eko := (not Bko) xor (Bku or Bka);
         Co  := Co xor Eko;
         Eku := Bku xor (Bka and Bke);
         Cu  := Cu xor Eku;

         Bma := Rotate_Left (Abu xor Du, 91 mod Lane_Type'Size);
         Bme := Rotate_Left (Aga xor Da, 36 mod Lane_Type'Size);
         Bmi := Rotate_Left (Ake xor De, 10 mod Lane_Type'Size);
         Bmo := Rotate_Left (Ami xor Di, 15 mod Lane_Type'Size);
         Bmu := Rotate_Left (Aso xor D0, 120 mod Lane_Type'Size);
         Ema := Bma xor (Bme and Bmi);
         Ca  := Ca xor Ema;
         Eme := Bme xor (Bmi or Bmo);
         Ce  := Ce xor Eme;
         Emi := Bmi xor ((not Bmo) or Bmu);
         Ci  := Ci xor Emi;
         Emo := (not Bmo) xor (Bmu and Bma);
         Co  := Co xor Emo;
         Emu := Bmu xor (Bma or Bme);
         Cu  := Cu xor Emu;

         Bsa := Rotate_Left (Abi xor Di, 190 mod Lane_Type'Size);
         Bse := Rotate_Left (Ago xor D0, 55 mod Lane_Type'Size);
         Bsi := Rotate_Left (Aku xor Du, 231 mod Lane_Type'Size);
         Bso := Rotate_Left (Ama xor Da, 105 mod Lane_Type'Size);
         Bsu := Rotate_Left (Ase xor De, 66 mod Lane_Type'Size);
         Esa := Bsa xor ((not Bse) and Bsi);
         Ca  := Ca xor Esa;
         Ese := (not Bse) xor (Bsi or Bso);
         Ce  := Ce xor Ese;
         Esi := Bsi xor (Bso and Bsu);
         Ci  := Ci xor Esi;
         Eso := Bso xor (Bsu or Bsa);
         Co  := Co xor Eso;
         Esu := Bsu xor (Bsa and Bse);
         Cu  := Cu xor Esu;

      end Theta_Rho_Pi_Chi_Iota_Prepare_Theta_AtoE;

      procedure Theta_Rho_Pi_Chi_Iota_Prepare_Theta_EtoA (RI : Round_Index)
      is
         Da, De, Di, D0, Du : Lane_Type;

         Bba, Bbe, Bbi, Bbo, Bbu : Lane_Type;
         Bga, Bge, Bgi, Bgo, Bgu : Lane_Type;
         Bka, Bke, Bki, Bko, Bku : Lane_Type;
         Bma, Bme, Bmi, Bmo, Bmu : Lane_Type;
         Bsa, Bse, Bsi, Bso, Bsu : Lane_Type;

      begin
         Da  := Cu xor Rotate_Left (Ce, 1);
         De  := Ca xor Rotate_Left (Ci, 1);
         Di  := Ce xor Rotate_Left (Co, 1);
         D0  := Ci xor Rotate_Left (Cu, 1);
         Du  := Co xor Rotate_Left (Ca, 1);

         Bba := Eba xor Da;
         Bbe := Rotate_Left (Ege xor De, 300 mod Lane_Type'Size);
         Bbi := Rotate_Left (Eki xor Di, 171 mod Lane_Type'Size);
         Bbo := Rotate_Left (Emo xor D0, 21 mod Lane_Type'Size);
         Bbu := Rotate_Left (Esu xor Du, 78 mod Lane_Type'Size);
         Aba := Bba xor (Bbe or Bbi);
         Aba := Aba xor Lane_Type (RC (RI) and (2**Lane_Type'Size - 1));
         Ca  := Aba;
         Abe := Bbe xor ((not Bbi) or Bbo);
         Ce  := Abe;
         Abi := Bbi xor (Bbo and Bbu);
         Ci  := Abi;
         Abo := Bbo xor (Bbu or Bba);
         Co  := Abo;
         Abu := Bbu xor (Bba and Bbe);
         Cu  := Abu;

         Bga := Rotate_Left (Ebo xor D0, 28 mod Lane_Type'Size);
         Bge := Rotate_Left (Egu xor Du, 276 mod Lane_Type'Size);
         Bgi := Rotate_Left (Eka xor Da, 3 mod Lane_Type'Size);
         Bgo := Rotate_Left (Eme xor De, 45 mod Lane_Type'Size);
         Bgu := Rotate_Left (Esi xor Di, 253 mod Lane_Type'Size);
         Aga := Bga xor (Bge or Bgi);
         Ca  := Ca xor Aga;
         Age := Bge xor (Bgi and Bgo);
         Ce  := Ce xor Age;
         Agi := Bgi xor (Bgo or (not Bgu));
         Ci  := Ci xor Agi;
         Ago := Bgo xor (Bgu or Bga);
         Co  := Co xor Ago;
         Agu := Bgu xor (Bga and Bge);
         Cu  := Cu xor Agu;

         Bka := Rotate_Left (Ebe xor De, 1 mod Lane_Type'Size);
         Bke := Rotate_Left (Egi xor Di, 6 mod Lane_Type'Size);
         Bki := Rotate_Left (Eko xor D0, 153 mod Lane_Type'Size);
         Bko := Rotate_Left (Emu xor Du, 136 mod Lane_Type'Size);
         Bku := Rotate_Left (Esa xor Da, 210 mod Lane_Type'Size);
         Aka := Bka xor (Bke or Bki);
         Ca  := Ca xor Aka;
         Ake := Bke xor (Bki and Bko);
         Ce  := Ce xor Ake;
         Aki := Bki xor ((not Bko) and Bku);
         Ci  := Ci xor Aki;
         Ako := (not Bko) xor (Bku or Bka);
         Co  := Co xor Ako;
         Aku := Bku xor (Bka and Bke);
         Cu  := Cu xor Aku;

         Bma := Rotate_Left (Ebu xor Du, 91 mod Lane_Type'Size);
         Bme := Rotate_Left (Ega xor Da, 36 mod Lane_Type'Size);
         Bmi := Rotate_Left (Eke xor De, 10 mod Lane_Type'Size);
         Bmo := Rotate_Left (Emi xor Di, 15 mod Lane_Type'Size);
         Bmu := Rotate_Left (Eso xor D0, 120 mod Lane_Type'Size);
         Ama := Bma xor (Bme and Bmi);
         Ca  := Ca xor Ama;
         Ame := Bme xor (Bmi or Bmo);
         Ce  := Ce xor Ame;
         Ami := Bmi xor ((not Bmo) or Bmu);
         Ci  := Ci xor Ami;
         Amo := (not Bmo) xor (Bmu and Bma);
         Co  := Co xor Amo;
         Amu := Bmu xor (Bma or Bme);
         Cu  := Cu xor Amu;

         Bsa := Rotate_Left (Ebi xor Di, 190 mod Lane_Type'Size);
         Bse := Rotate_Left (Ego xor D0, 55 mod Lane_Type'Size);
         Bsi := Rotate_Left (Eku xor Du, 231 mod Lane_Type'Size);
         Bso := Rotate_Left (Ema xor Da, 105 mod Lane_Type'Size);
         Bsu := Rotate_Left (Ese xor De, 66 mod Lane_Type'Size);
         Asa := Bsa xor ((not Bse) and Bsi);
         Ca  := Ca xor Asa;
         Ase := (not Bse) xor (Bsi or Bso);
         Ce  := Ce xor Ase;
         Asi := Bsi xor (Bso and Bsu);
         Ci  := Ci xor Asi;
         Aso := Bso xor (Bsu or Bsa);
         Co  := Co xor Aso;
         Asu := Bsu xor (Bsa and Bse);
         Cu  := Cu xor Asu;
      end Theta_Rho_Pi_Chi_Iota_Prepare_Theta_EtoA;

   begin
      Copy_From_State;

      Prepare_Theta;

      for RI in 0 .. (Num_Rounds / 2) - 1 loop
         Theta_Rho_Pi_Chi_Iota_Prepare_Theta_AtoE
           (First_Round + Round_Index (RI * 2));

         Theta_Rho_Pi_Chi_Iota_Prepare_Theta_EtoA
           (First_Round + Round_Index ((RI * 2) + 1));
      end loop;

      Copy_To_State_From_A;

   end Permute;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) renames Sanitize_Context;

end Tux.Generic_Keccak;