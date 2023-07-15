--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  @summary
--  Utilities for sanitizing sensitive data from memory.
--
--  @description
--  This package implements the guidance from the paper "Sanitizing Sensitive
--  Data: How to get it Right (or at least Less Wrong...)" by Roderick Chapman
--  to reduce the risk of the compiler optimizing away the sanitization code.
package Tux.Sanitization with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   generic
      type Index_Type is (<>);
      type Element_Type is private;
      Sanitize_Value : Element_Type;
      type Array_Type is array (Index_Type range <>) of Element_Type;
   procedure Generic_Sanitize_Array (Target : out Array_Type) with
     No_Inline,
     Global => null,
     Post   => (for all Element of Target => Element = Sanitize_Value);

   generic
      type Element_Type is private;
      Sanitize_Value : Element_Type;
   procedure Generic_Sanitize (Target : out Element_Type) with
     No_Inline,
     Global => null,
     Post   => Target = Sanitize_Value;

private

   procedure Memory_Fence with
     Import,
     Global        => null,
     Convention    => Intrinsic,
     External_Name => "__sync_synchronize",
     Annotate      => (GNATprove, Terminating);

end Tux.Sanitization;
