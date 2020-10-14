// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// 2019 OKIMS

// SPDX-License-Identifier: MIT

pragma solidity <= 0.7.3;

library Pairing {

    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero. 
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {

        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
     * @return The sum of two points of G1
     */
    function plus(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {

        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-add-failed");
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {

        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success,"pairing-mul-failed");
    }

    /* @return The result of computing the pairing check
     *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
     *         For example,
     *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
     */
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {

        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];

        uint256 inputSize = 24;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 4; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-opcode-failed");

        return out[0] != 0;
    }
}

contract QuadVoteTallyVerifier {

    using Pairing for *;

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[11] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alpha1 = Pairing.G1Point(uint256(20364538628575183800728855301826674388007016937028054074021996434586335930661),uint256(13622611132523507138764696849384460482273454296276128344736017353097831764332));
        vk.beta2 = Pairing.G2Point([uint256(20121196271677149491183175421238753925202082234907814277199613201684165663566),uint256(7610540675287302646507895768762575729448444924736071669459920287847916979251)], [uint256(2354237551776583259084444843371606310623033999004785096523846074749571898212),uint256(12534188653563457582225583217724948835833781361955878716336887631336069221733)]);
        vk.gamma2 = Pairing.G2Point([uint256(6120748796257641055309021223860912693179681637403703290889447326699880656864),uint256(5874103118971645158051556437712860276619981479385668041561371896064712002034)], [uint256(10573074597810041086450592421310240754328557381734638420705031997007757377429),uint256(20532209783786941343037548292141677868530407545048170182264448922586919925296)]);
        vk.delta2 = Pairing.G2Point([uint256(5655227016402053711893462764306594837499709176803481509672907708340603623270),uint256(9953982277013140983086848481996702517372168205118454401050411267045155840560)], [uint256(11370948956980289729521375369142968126898360312794934387727682654975796305537),uint256(5234963726941762718168851368259468292833580651124840216719832932367183684203)]);
        vk.IC[0] = Pairing.G1Point(uint256(14431015338349896000618097048647167275000235336219659360927335768302153037527),uint256(6542925138154244421681125670613823419319193019165516032067393638456141290443));
        vk.IC[1] = Pairing.G1Point(uint256(17783350061836208157696167507432505957410453203573813405640153799145070605247),uint256(18215431523001798056903956519520947800819645663188386212255615255109722965600));
        vk.IC[2] = Pairing.G1Point(uint256(5336032732022211123820255349758074727131001060859228433908111330080463466422),uint256(8063872741638793921562821894403556349533561271819974708210459335340806509588));
        vk.IC[3] = Pairing.G1Point(uint256(3731398183110001249282723216318256533699883818713125844990077786997535549283),uint256(1830816343700378421659267235731124415482792513054022160893009203747964651355));
        vk.IC[4] = Pairing.G1Point(uint256(16657566065746368427695386734513923581012104685587826437316102359420753444118),uint256(21858889368253209804496473280021053689960499486332437257422022559427842977509));
        vk.IC[5] = Pairing.G1Point(uint256(17124305686014333245950063108678552600819256545326188767821685736190676430593),uint256(5533564482472462210997151705082487154652923137804707758710774933418952986785));
        vk.IC[6] = Pairing.G1Point(uint256(18283384700155352331196210264592604082404767127890502741134301122502851327109),uint256(19905856154221854800231612386653193980295622394163272628652755408741420532199));
        vk.IC[7] = Pairing.G1Point(uint256(7832172188696725900476193871115860727147847770073444327003566613205558576930),uint256(77735583834062533157394471014018830655005605603127769272062929747029965622));
        vk.IC[8] = Pairing.G1Point(uint256(8116944482709903613370831401091123971690526155110252363844994134585623226598),uint256(3232820093198921558816193734005447386310391405231930909405053078158891901811));
        vk.IC[9] = Pairing.G1Point(uint256(3299606031460213005597990483358702576087227197589880895318238496740120223574),uint256(15730037090209648887926428217085583975119004452232902164383779791036375826832));
        vk.IC[10] = Pairing.G1Point(uint256(21372907835130586580081739130290491711857896710156351347502561531077379006982),uint256(11657529212644892093851649475075456425983247415474716260166406167307719743022));

    }
    
    /*
     * @returns Whether the proof is valid given the hardcoded verifying key
     *          above and the public inputs
     */
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory input
    ) public view returns (bool) {

        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        VerifyingKey memory vk = verifyingKey();

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);

        // Make sure that proof.A, B, and C are each less than the prime q
        require(proof.A.X < PRIME_Q, "verifier-aX-gte-prime-q");
        require(proof.A.Y < PRIME_Q, "verifier-aY-gte-prime-q");

        require(proof.B.X[0] < PRIME_Q, "verifier-bX0-gte-prime-q");
        require(proof.B.Y[0] < PRIME_Q, "verifier-bY0-gte-prime-q");

        require(proof.B.X[1] < PRIME_Q, "verifier-bX1-gte-prime-q");
        require(proof.B.Y[1] < PRIME_Q, "verifier-bY1-gte-prime-q");

        require(proof.C.X < PRIME_Q, "verifier-cX-gte-prime-q");
        require(proof.C.Y < PRIME_Q, "verifier-cY-gte-prime-q");

        // Make sure that every input is less than the snark scalar field
        //for (uint256 i = 0; i < input.length; i++) {
        for (uint256 i = 0; i < 10; i++) {
            require(input[i] < SNARK_SCALAR_FIELD,"verifier-gte-snark-scalar-field");
            vk_x = Pairing.plus(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }

        vk_x = Pairing.plus(vk_x, vk.IC[0]);

        return Pairing.pairing(
            Pairing.negate(proof.A),
            proof.B,
            vk.alpha1,
            vk.beta2,
            vk_x,
            vk.gamma2,
            proof.C,
            vk.delta2
        );
    }
}
