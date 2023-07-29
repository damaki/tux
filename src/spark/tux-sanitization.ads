--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  @summary
--  Utilities for securely sanitizing sensitive data from memory.
--
--  @description
--  This package should be used to clear sensitive data from memory when
--  they are no longer needed. For example, clearing a buffer on the stack -
--  that contained sensitive data - before it goes out of scope.
--
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
      --  Index type for the array

      type Element_Type is private;
      --  Type of the array elements

      Sanitize_Value : Element_Type;
      --  Sanitizing an array sets all elements to this value

      type Array_Type is array (Index_Type range <>) of Element_Type;
      --  The array type to sanitize

   procedure Generic_Sanitize_Array (Target : out Array_Type) with
     No_Inline,
     Global  => null,
     Depends => (Target => Target),
     Post    => (for all Element of Target => Element = Sanitize_Value);
   --  Securely sanitize an array.
   --
   --  This clears an array by setting all elements to the specified
   --  Sanitize_Value.
   --
   --  @param Target The array to be sanitized.

   generic
      type Element_Type is private;
      --  Selects the type of objects to be sanitized

      Sanitize_Value : Element_Type;
      --  Sanitizing an object sets it to this value

   procedure Generic_Sanitize (Target : out Element_Type) with
     No_Inline,
     Global  => null,
     Depends => (Target => null),
     Post    => Target = Sanitize_Value;
   --  Securely sanitize an object.
   --
   --  This clears an object by setting it to the specified Sanitize_Value.
   --
   --  @param Target The object to be sanitized.

private

   procedure Memory_Fence with
     Import,
     Global        => null,
     Convention    => Intrinsic,
     External_Name => "__sync_synchronize",
     Annotate      => (GNATprove, Terminating);

end Tux.Sanitization;
