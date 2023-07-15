--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.Hashing with
  SPARK_Mode
is

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHA1 =>
            Tux.SHA1.Initialize (Ctx.SHA1_Ctx);

         when SHA224 =>
            Tux.SHA256.Initialize (Ctx.SHA224_Ctx);

         when SHA256 =>
            Tux.SHA256.Initialize (Ctx.SHA256_Ctx);

         when SHA384 =>
            Tux.SHA512.Initialize (Ctx.SHA384_Ctx);

         when SHA512 =>
            Tux.SHA512.Initialize (Ctx.SHA512_Ctx);

         when SHA512_224 =>
            Tux.SHA512.Initialize (Ctx.SHA512_224_Ctx);

         when SHA512_256 =>
            Tux.SHA512.Initialize (Ctx.SHA512_256_Ctx);
      end case;
   end Initialize;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHA1 =>
            Tux.SHA1.Sanitize (Ctx.SHA1_Ctx);

         when SHA224 =>
            Tux.SHA256.Sanitize (Ctx.SHA224_Ctx);

         when SHA256 =>
            Tux.SHA256.Sanitize (Ctx.SHA256_Ctx);

         when SHA384 =>
            Tux.SHA512.Sanitize (Ctx.SHA384_Ctx);

         when SHA512 =>
            Tux.SHA512.Sanitize (Ctx.SHA512_Ctx);

         when SHA512_224 =>
            Tux.SHA512.Sanitize (Ctx.SHA512_224_Ctx);

         when SHA512_256 =>
            Tux.SHA512.Sanitize (Ctx.SHA512_256_Ctx);
      end case;
   end Sanitize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
   begin
      case Ctx.Algorithm is
         when SHA1 =>
            Tux.SHA1.Update (Ctx.SHA1_Ctx, Data);

         when SHA224 =>
            Tux.SHA256.Update (Ctx.SHA224_Ctx, Data);

         when SHA256 =>
            Tux.SHA256.Update (Ctx.SHA256_Ctx, Data);

         when SHA384 =>
            Tux.SHA512.Update (Ctx.SHA384_Ctx, Data);

         when SHA512 =>
            Tux.SHA512.Update (Ctx.SHA512_Ctx, Data);

         when SHA512_224 =>
            Tux.SHA512.Update (Ctx.SHA512_224_Ctx, Data);

         when SHA512_256 =>
            Tux.SHA512.Update (Ctx.SHA512_256_Ctx, Data);
      end case;
   end Update;

   ------------
   -- Finish --
   ------------

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Byte_Array)
   is
   begin
      case Ctx.Algorithm is
         when SHA1 =>
            Tux.SHA1.Finish (Ctx.SHA1_Ctx, Hash);

         when SHA224 =>
            Tux.SHA256.Finish (Ctx.SHA224_Ctx, Hash);

         when SHA256 =>
            Tux.SHA256.Finish (Ctx.SHA256_Ctx, Hash);

         when SHA384 =>
            Tux.SHA512.Finish (Ctx.SHA384_Ctx, Hash);

         when SHA512 =>
            Tux.SHA512.Finish (Ctx.SHA512_Ctx, Hash);

         when SHA512_224 =>
            Tux.SHA512.Finish (Ctx.SHA512_224_Ctx, Hash);

         when SHA512_256 =>
            Tux.SHA512.Finish (Ctx.SHA512_256_Ctx, Hash);
      end case;
   end Finish;

   -----------------------
   -- Finish_And_Verify --
   -----------------------

   procedure Finish_And_Verify
     (Ctx           : in out Context;
      Expected_Hash :        Byte_Array;
      Valid         :    out Boolean)
   is
      HLen : constant Hash_Length_Number := Hash_Length (Ctx.Algorithm);
      Hash : Byte_Array (1 .. HLen);

   begin
      Finish (Ctx, Hash);

      Valid := Equal_Constant_Time
                 (Expected_Hash, (Hash (1 .. Expected_Hash'Length)));

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Hash);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Hash);
   end Finish_And_Verify;

   ------------------
   -- Compute_Hash --
   ------------------

   procedure Compute_Hash
     (Algorithm :     Enabled_Algorithm_Kind;
      Data      :     Byte_Array;
      Hash      : out Byte_Array)
   is
   begin
      case Algorithm is
         when SHA1 =>
            Tux.SHA1.Compute_Hash (Data, Hash);

         when SHA224 =>
            Tux.SHA256.Compute_Hash (Tux.SHA256.SHA224, Data, Hash);

         when SHA256 =>
            Tux.SHA256.Compute_Hash (Tux.SHA256.SHA256, Data, Hash);

         when SHA384 =>
            Tux.SHA512.Compute_Hash (Tux.SHA512.SHA384, Data, Hash);

         when SHA512 =>
            Tux.SHA512.Compute_Hash (Tux.SHA512.SHA512, Data, Hash);

         when SHA512_224 =>
            Tux.SHA512.Compute_Hash (Tux.SHA512.SHA512_224, Data, Hash);

         when SHA512_256 =>
            Tux.SHA512.Compute_Hash (Tux.SHA512.SHA512_256, Data, Hash);
      end case;
   end Compute_Hash;

   -----------------
   -- Verify_Hash --
   -----------------

   function Verify_Hash
     (Algorithm     : Enabled_Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   is
   begin
      case Algorithm is
         when SHA1 =>
            return Tux.SHA1.Verify_Hash (Data, Expected_Hash);

         when SHA224 =>
            return Tux.SHA256.Verify_Hash
              (Tux.SHA256.SHA224, Data, Expected_Hash);

         when SHA256 =>
            return Tux.SHA256.Verify_Hash
              (Tux.SHA256.SHA256, Data, Expected_Hash);

         when SHA384 =>
            return Tux.SHA512.Verify_Hash
              (Tux.SHA512.SHA384, Data, Expected_Hash);

         when SHA512 =>
            return Tux.SHA512.Verify_Hash
              (Tux.SHA512.SHA512, Data, Expected_Hash);

         when SHA512_224 =>
            return Tux.SHA512.Verify_Hash
              (Tux.SHA512.SHA512_224, Data, Expected_Hash);

         when SHA512_256 =>
            return Tux.SHA512.Verify_Hash
              (Tux.SHA512.SHA512_256, Data, Expected_Hash);
      end case;
   end Verify_Hash;

end Tux.Hashing;
