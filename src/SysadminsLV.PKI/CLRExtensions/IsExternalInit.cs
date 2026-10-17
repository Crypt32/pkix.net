#if !NET5_0_OR_GREATER
using System.ComponentModel;

// ReSharper disable once CheckNamespace
namespace System.Runtime.CompilerServices;

/// <summary>
/// Compiler-only polyfill that enables C# <c>init</c> accessors and <c>record</c> types on target frameworks
/// that don't define this type (netstandard2.0, net472). It has no runtime behavior.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
internal static class IsExternalInit;
#endif
