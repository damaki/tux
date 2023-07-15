--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This package provides access to some of the privates part of the SHA-512
--  implementation for testing purposes.
with Interfaces; use Interfaces;

package Tux.SHA512.Test_Access with
  Preelaborate
is

   procedure Set_Byte_Length
     (Ctx  : in out Context;
      Low  :        Unsigned_64;
      High :        Unsigned_64);

   function Get_Byte_Length_Low  (Ctx : Context) return Unsigned_64;
   function Get_Byte_Length_High (Ctx : Context) return Unsigned_64;

end Tux.SHA512.Test_Access;