package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// printNegG2 prints -G2 in the pairing check's order: x_imag|x_real|y_imag|y_real.
func printNegG2() {
	_, _, _, g2 := bn254.Generators()
	var n bn254.G2Affine
	n.Neg(&g2)
	xi, xr, yi, yr := n.X.A1.Bytes(), n.X.A0.Bytes(), n.Y.A1.Bytes(), n.Y.A0.Bytes()
	fmt.Printf("negG2 = %x%x%x%x\n", xi, xr, yi, yr)
}
