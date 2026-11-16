# Code and GUI optimization verification

Verified on 16 November 2026 on Windows with Python 3.14, Tk 9.0 and Node 24. Browser GUI checks used Brave at 390 x 844 against a disposable local feedback database.

100 targeted verification checks passed. These are distinct checks of the improved code and GUI, not a claim of 100 independent rewrites or a speedup percentage.

## Changes

- Desktop encryption/decryption runs in a single worker; Tk polls results without worker access to widgets. Busy controls prevent conflicting actions, recover after failure and cancel polling on close.
- Scoped Enter/Ctrl+Enter shortcuts avoid accidental generation while editing secrets. New and failed generation clears stale ciphertext.
- Browser crypto has explicit password state, busy controls and accessible progress messages; passwords up to 128 characters fit responsive layouts.
- Clipboard fallback always removes its temporary field and restores focus, including failures.
- Missing feedback APIs on static hosting show an explanation and hide the unusable form; transient errors remain retryable.
- Malformed Python ciphertext is rejected before expensive key derivation; duplicate category selections are normalized.
- GitHub Pages now depends on passing Python/JavaScript checks and packages application assets without test modules.

## Additional validation

19 Python tests and 8 JavaScript tests passed, including desktop worker lifecycle and real browser/Python encryption interoperability for ASCII, Unicode and 128-character passwords. Static-host fallback was verified with a separate static HTTP server. Source design evaluation passed; only same-provider evaluation was available. The GitHub Actions workflow was updated and locally inspected; it has not been executed on GitHub or deployed. Desktop GUI tests skip when no display is available.

## Reproduce

Run `python -m unittest discover -v`, `node --test web/*.test.mjs` and `python scripts/verify_optimizations.py`. For the final 10 GUI checks, use a disposable `feedback_server.py --database TEMP_PATH` preview at viewport width 390 and evaluate `scripts/verify_browser.js` in that page. This submits one test feedback response. See README for server and deployment limits.

## Individual results

1. PASS ? Desktop generator: mask 0001, length 1
2. PASS ? Desktop generator: mask 0001, length 128
3. PASS ? Desktop generator: mask 0010, length 1
4. PASS ? Desktop generator: mask 0010, length 128
5. PASS ? Desktop generator: mask 0011, length 2
6. PASS ? Desktop generator: mask 0011, length 128
7. PASS ? Desktop generator: mask 0100, length 1
8. PASS ? Desktop generator: mask 0100, length 128
9. PASS ? Desktop generator: mask 0101, length 2
10. PASS ? Desktop generator: mask 0101, length 128
11. PASS ? Desktop generator: mask 0110, length 2
12. PASS ? Desktop generator: mask 0110, length 128
13. PASS ? Desktop generator: mask 0111, length 3
14. PASS ? Desktop generator: mask 0111, length 128
15. PASS ? Desktop generator: mask 1000, length 1
16. PASS ? Desktop generator: mask 1000, length 128
17. PASS ? Desktop generator: mask 1001, length 2
18. PASS ? Desktop generator: mask 1001, length 128
19. PASS ? Desktop generator: mask 1010, length 2
20. PASS ? Desktop generator: mask 1010, length 128
21. PASS ? Desktop generator: mask 1011, length 3
22. PASS ? Desktop generator: mask 1011, length 128
23. PASS ? Desktop generator: mask 1100, length 2
24. PASS ? Desktop generator: mask 1100, length 128
25. PASS ? Desktop generator: mask 1101, length 3
26. PASS ? Desktop generator: mask 1101, length 128
27. PASS ? Desktop generator: mask 1110, length 3
28. PASS ? Desktop generator: mask 1110, length 128
29. PASS ? Desktop generator: mask 1111, length 4
30. PASS ? Desktop generator: mask 1111, length 128
31. PASS ? Desktop validation: length=0, categories=['a']
32. PASS ? Desktop validation: length=-1, categories=['a']
33. PASS ? Desktop validation: length=129, categories=['a']
34. PASS ? Desktop validation: length=1.5, categories=['a']
35. PASS ? Desktop validation: length=True, categories=['a']
36. PASS ? Desktop validation: length=16, categories=[]
37. PASS ? Desktop validation: length=16, categories=None
38. PASS ? Desktop validation: length=16, categories='abc'
39. PASS ? Desktop validation: length=16, categories=['']
40. PASS ? Desktop validation: length=1, categories=['a', 'b']
41. PASS ? Browser generator: lowercase, length 1
42. PASS ? Browser generator: lowercase, length 128
43. PASS ? Browser generator: uppercase, length 1
44. PASS ? Browser generator: uppercase, length 128
45. PASS ? Browser generator: lowercase+uppercase, length 2
46. PASS ? Browser generator: lowercase+uppercase, length 128
47. PASS ? Browser generator: digits, length 1
48. PASS ? Browser generator: digits, length 128
49. PASS ? Browser generator: lowercase+digits, length 2
50. PASS ? Browser generator: lowercase+digits, length 128
51. PASS ? Browser generator: uppercase+digits, length 2
52. PASS ? Browser generator: uppercase+digits, length 128
53. PASS ? Browser generator: lowercase+uppercase+digits, length 3
54. PASS ? Browser generator: lowercase+uppercase+digits, length 128
55. PASS ? Browser generator: symbols, length 1
56. PASS ? Browser generator: symbols, length 128
57. PASS ? Browser generator: lowercase+symbols, length 2
58. PASS ? Browser generator: lowercase+symbols, length 128
59. PASS ? Browser generator: uppercase+symbols, length 2
60. PASS ? Browser generator: uppercase+symbols, length 128
61. PASS ? Browser generator: lowercase+uppercase+symbols, length 3
62. PASS ? Browser generator: lowercase+uppercase+symbols, length 128
63. PASS ? Browser generator: digits+symbols, length 2
64. PASS ? Browser generator: digits+symbols, length 128
65. PASS ? Browser generator: lowercase+digits+symbols, length 3
66. PASS ? Browser generator: lowercase+digits+symbols, length 128
67. PASS ? Browser generator: uppercase+digits+symbols, length 3
68. PASS ? Browser generator: uppercase+digits+symbols, length 128
69. PASS ? Browser generator: lowercase+uppercase+digits+symbols, length 4
70. PASS ? Browser generator: lowercase+uppercase+digits+symbols, length 128
71. PASS ? Browser validation: zero length
72. PASS ? Browser validation: negative length
73. PASS ? Browser validation: oversized length
74. PASS ? Browser validation: fractional length
75. PASS ? Browser validation: boolean length
76. PASS ? Browser validation: empty categories
77. PASS ? Browser validation: null categories
78. PASS ? Browser validation: string categories
79. PASS ? Browser validation: prototype property
80. PASS ? Browser validation: insufficient length
81. PASS ? Desktop GUI: empty passphrase masked
82. PASS ? Desktop GUI: reveal toggle updates label
83. PASS ? Desktop GUI: generate populates password
84. PASS ? Desktop GUI: generation clears stale ciphertext
85. PASS ? Desktop GUI: invalid length gives feedback
86. PASS ? Desktop GUI: missing passphrase rejected without work
87. PASS ? Desktop GUI: crypto disables conflicting actions
88. PASS ? Desktop GUI: generating during crypto preserves snapshot
89. PASS ? Desktop GUI: event loop responsive during worker
90. PASS ? Desktop GUI: completion restores controls and result
91. PASS ? Browser GUI: empty categories show error
92. PASS ? Browser GUI: digit-only password and length display
93. PASS ? Browser GUI: maximum length covers all character types
94. PASS ? Browser GUI: passphrase toggle is accessible
95. PASS ? Browser GUI: crypto locks conflicting controls
96. PASS ? Browser GUI: encryption finishes and restores controls
97. PASS ? Browser GUI: decrypted password round trips
98. PASS ? Browser GUI: fresh generation clears old ciphertext
99. PASS ? Browser GUI: shared feedback saves and refreshes count
100. PASS ? Browser GUI: narrow layout has no horizontal overflow
