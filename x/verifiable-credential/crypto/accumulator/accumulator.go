package accumulator

import (
	crand "crypto/rand"
	"errors"
	"fmt"

	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto"

	accumcrypto "github.com/coinbase/kryptology/pkg/accumulator"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

var Curve = curves.BLS12381(&curves.PointBls12381G1{})

func NewAccumulatorSchema() (*PrivateKey, *PublicParameters, error) {
	var ikm [32]byte
	cnt, err := crand.Read(ikm[:])
	if err != nil {
		return nil, nil, err
	}
	if cnt != 32 {
		return nil, nil, fmt.Errorf("unable to read sufficient random data")
	}

	sk, err := new(accumcrypto.SecretKey).New(Curve, ikm[:])
	if err != nil {
		return nil, nil, err
	}

	pk, err := sk.GetPublicKey(Curve)
	if err != nil {
		return nil, nil, err
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return &PrivateKey{Value: skBytes}, &PublicParameters{PublicKey: pkBytes}, nil
}

func (pp *PublicParameters) InitAccumulator(ask *PrivateKey, members accumcrypto.ElementSet) (*PublicParameters, error) {
	sk := new(accumcrypto.SecretKey)
	err := sk.UnmarshalBinary(ask.Value)
	if err != nil {
		return nil, err
	}
	accum, err := new(accumcrypto.Accumulator).WithElements(Curve, sk, members.Elements)
	if err != nil {
		return nil, err
	}
	acc, err := accum.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pp.State = &State{AccValue: acc, Update: nil}

	return pp, err
}

func (ask *PrivateKey) InitMemberWitness(pp *PublicParameters, member accumcrypto.Element) (wit []byte, err error) {
	sk := new(accumcrypto.SecretKey)
	err = sk.UnmarshalBinary(ask.Value)
	if err != nil {
		return nil, err
	}

	accum := new(accumcrypto.Accumulator)
	err = accum.UnmarshalBinary(pp.State.AccValue)
	if err != nil {
		return nil, err
	}
	witness, err := new(accumcrypto.MembershipWitness).New(member, accum, sk)
	if err != nil {
		return nil, err
	}
	return witness.MarshalBinary()
}

func CreateMembershipProofPre(pp *PublicParameters, wit []byte, eb *accumcrypto.ExternalBlinding) (mpc *accumcrypto.MembershipProofCommitting, accumOkm []byte, proofEntropy []byte, err error) {
	pk := new(accumcrypto.PublicKey)
	err = pk.UnmarshalBinary(pp.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	var entropy [32]byte
	cnt, err := crand.Read(entropy[:])
	if err != nil {
		return nil, nil, nil, err
	}
	if cnt != 32 {
		return nil, nil, nil, errors.New("unable to read sufficient random data")
	}

	params, err := new(accumcrypto.ProofParams).New(Curve, pk, entropy[:])

	witness := new(accumcrypto.MembershipWitness)
	err = witness.UnmarshalBinary(wit)
	if err != nil {
		return nil, nil, nil, err
	}

	accum := new(accumcrypto.Accumulator)
	err = accum.UnmarshalBinary(pp.State.AccValue)
	if err != nil {
		return nil, nil, nil, err
	}

	mpc, err = new(accumcrypto.MembershipProofCommitting).New(witness, accum, params, pk, eb)
	if err != nil {
		return nil, nil, nil, err
	}
	accumOkm = mpc.GetChallengeBytes()

	return mpc, accumOkm, entropy[:], err
}

func GetChallenge(okm []byte) curves.Scalar {
	prefix := []byte(crypto.ChallengePrefix)
	c := append(prefix, okm...)
	return Curve.Scalar.Hash(c)
}

func CreateMembershipProofPost(mpc *accumcrypto.MembershipProofCommitting, challengeOkm []byte) (proof []byte, err error) {
	// generate the final membership proof
	challenge := GetChallenge(challengeOkm)
	memProof := mpc.GenProof(challenge)
	return memProof.MarshalBinary()
}

func VerifyMembershipProof(pp *PublicParameters, proofEntropy []byte, challengeOkm []byte, proof []byte) (accOkm []byte, err error) {
	pk := new(accumcrypto.PublicKey)
	err = pk.UnmarshalBinary(pp.PublicKey)
	if err != nil {
		return nil, err
	}

	accum := new(accumcrypto.Accumulator)
	err = accum.UnmarshalBinary(pp.State.AccValue)
	if err != nil {
		return nil, err
	}

	// recreate generators to make sure they are not co-related
	params, err := new(accumcrypto.ProofParams).New(Curve, pk, proofEntropy[:])
	if err != nil {
		return nil, err
	}

	challenge := GetChallenge(challengeOkm)

	memProof := new(accumcrypto.MembershipProof)
	err = memProof.UnmarshalBinary(proof)
	if err != nil {
		return nil, err
	}
	finalProof, err := memProof.Finalize(accum, params, pk, challenge)
	if err != nil {
		return nil, err
	}
	accOkm = finalProof.GetChallengeBytes(Curve)

	return accOkm, err
}

func (pp *PublicParameters) UpdateAccumulator(ask *PrivateKey, adds accumcrypto.ElementSet, dels accumcrypto.ElementSet) (*PublicParameters, error) {
	sk := new(accumcrypto.SecretKey)
	err := sk.UnmarshalBinary(ask.Value)
	if err != nil {
		return nil, err
	}

	accum := new(accumcrypto.Accumulator)
	accum.UnmarshalBinary(pp.State.AccValue)
	newAccum, coeffs, err := accum.Update(sk, adds.Elements, dels.Elements)
	if err != nil {
		return nil, err
	}
	newAcc, err := newAccum.MarshalBinary()

	additions, err := adds.MarshalBinary()
	if err != nil {
		return nil, err
	}

	deletions, err := dels.MarshalBinary()
	if err != nil {
		return nil, err
	}

	coffSet := accumcrypto.CoefficientSet{coeffs}
	coefficients, err := coffSet.MarshalBinary()

	batchUpdate := BatchUpdate{additions, deletions, coefficients}
	pp.State = &State{newAcc, &batchUpdate}

	return pp, nil
}

func UpdateWitness(pp *PublicParameters, wit []byte) (newWit []byte, err error) {
	pk := new(accumcrypto.PublicKey)
	err = pk.UnmarshalBinary(pp.PublicKey)
	if err != nil {
		return nil, err
	}

	accum := new(accumcrypto.Accumulator)
	accum.UnmarshalBinary(pp.State.AccValue)

	witness := new(accumcrypto.MembershipWitness)
	err = witness.UnmarshalBinary(wit)
	if err != nil {
		return nil, err
	}

	adds := new(accumcrypto.ElementSet)
	err = adds.UnmarshalBinary(pp.State.Update.Additions)
	if err != nil {
		return nil, err
	}

	dels := new(accumcrypto.ElementSet)
	err = dels.UnmarshalBinary(pp.State.Update.Deletions)
	if err != nil {
		return nil, err
	}

	coeffs := new(accumcrypto.CoefficientSet)
	err = coeffs.UnmarshalBinary(pp.State.Update.Coefficients)
	if err != nil {
		return nil, err
	}

	newWitness, err := witness.BatchUpdate(adds.Elements, dels.Elements, coeffs.Coefficients)
	if err != nil {
		return nil, err
	}
	err = newWitness.Verify(pk, accum)
	if err != nil {
		return nil, err
	}

	return newWitness.MarshalBinary()
}

func GetPublicBlinding(proof []byte) ([]byte, error) {
	memProof := new(accumcrypto.MembershipProof)
	err := memProof.UnmarshalBinary(proof)
	if err != nil {
		return nil, err
	}

	s := memProof.GetPublicBlinding()
	return s.Bytes(), nil
}
