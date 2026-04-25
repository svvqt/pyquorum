## Known Security Issues

This library is in early development (0.x.x) and has known vulnerabilities:

- **[HIGH]** Secret key split into 4×64-bit chunks weakening 256-bit security
- **[MEDIUM]** Timing leak in modular multiplication (mul_mod)  
- **[MEDIUM]** Gaussian elimination in Blakley scheme is not constant-time

These issues are tracked and will be fixed before 1.0.0 release.