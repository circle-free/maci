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

pragma solidity ^0.7.3;

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

contract BatchUpdateStateTreeVerifier {

    using Pairing for *;

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[21] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alpha1 = Pairing.G1Point(uint256(19418248642104233853382022377337822364483360667364786322137768705648391330331),uint256(20846337609854002683342578543188974783093341753906719094365661415978882617703));
        vk.beta2 = Pairing.G2Point([uint256(4738603458169714172967932388024815024929721140879658108844238563885191853747),uint256(3339485935295512654728555766787385449609563582172140728001209265135174394537)], [uint256(6278989137556787060428504622032395478369118083392728917006877935763630067824),uint256(17241145765251867178891939272606051807761124584749045221749522638661016924119)]);
        vk.gamma2 = Pairing.G2Point([uint256(20911354891183819398982238734091404466624808855012368233624830406535014138669),uint256(6647402115109731943195426868678672591291522297617484719995558212840095726158)], [uint256(21543883314638310359861238572588137242725190066270291117235768236452024387075),uint256(870194423786654338527997284707563244481730613496605649278723040924439376233)]);
        vk.delta2 = Pairing.G2Point([uint256(13466450853116752740705343285973862273263834730761965557584359896497801867111),uint256(16402334686714498533596694644403916920799832087892138141687322205923074494306)], [uint256(8800052179391751734582497441235398414747862553205613777173845722484684605375),uint256(7695202647427276527681961515267643903856914326831772767910088615898301548007)]);
        vk.IC[0] = Pairing.G1Point(uint256(20508743474970831670835798949448080418770159399075178557879754257249222387336),uint256(19586840876900474630545483891848293185576655275941770757422363541431966771354));
        vk.IC[1] = Pairing.G1Point(uint256(18348513143461716601828781289262543004638915951648946927592970510726674786270),uint256(20584333964635815289261810682867306039431850804467632090799172991709690107442));
        vk.IC[2] = Pairing.G1Point(uint256(1215663718313611588865385001916666723031940776301746043347046639142348235993),uint256(14337440397174207617458094283643488434010414622480614219010939614031940451344));
        vk.IC[3] = Pairing.G1Point(uint256(6362873683636724407061508970237870752980057866236038032220003556315048131390),uint256(15650123237210586384473055556659904213940777166520357006806479658007239451940));
        vk.IC[4] = Pairing.G1Point(uint256(6176757724707042569070690572840552732245354057972318614078895834686444527040),uint256(10220634458044631969776335792463343266968243545235008515766409170533885003448));
        vk.IC[5] = Pairing.G1Point(uint256(13759532307492044303786693712195413980229164583352732130183696440700547018571),uint256(6999929839714779113521240650564140765110160682235893572444709977915845701117));
        vk.IC[6] = Pairing.G1Point(uint256(11965346977235379287948390810095245428466968760758214339040250727274995241684),uint256(18522695067496823358536343589844693867752670500139062899629013619495808635512));
        vk.IC[7] = Pairing.G1Point(uint256(15255148373801968550360775588446685223403260242676351020456365154224380943879),uint256(17330157200299087133582488566141497463459445056892410575134675735511224412895));
        vk.IC[8] = Pairing.G1Point(uint256(3179061596011456206196888533653538845158702608614771326534645274821273143557),uint256(2179365803577126774848583352924772618809848687813171884025250137330679992035));
        vk.IC[9] = Pairing.G1Point(uint256(15306890746162342848112532326861655192658870981995917388622511084856505191316),uint256(5621943098745451905139917457162880050630820042470936785882956311625098812550));
        vk.IC[10] = Pairing.G1Point(uint256(7141974791345702691468922597453197115790430415140469100397578144856923019019),uint256(20098975738719746246419656464914784338256643547832658799647129299243490042059));
        vk.IC[11] = Pairing.G1Point(uint256(4328765369523433718011334440226623191358764746334102291972963165627959631912),uint256(12411311252093496364907231231338992397779345025144421564369564767146865346056));
        vk.IC[12] = Pairing.G1Point(uint256(9748152200775420931549406917429041167442823305736569583595438940419121726527),uint256(4820274899811494972322505847794329367559048291208059572846042994344805006461));
        vk.IC[13] = Pairing.G1Point(uint256(8584496385808069836071069130108630741672416893199185206258071502047720483961),uint256(5203403923178751082946158604621713180346949648901018369020194674286697548096));
        vk.IC[14] = Pairing.G1Point(uint256(20484412449022423047870403235463820841730843304956473422203692091512114420024),uint256(13577474903392633711647000925983694353938577663099511369586323391955808081665));
        vk.IC[15] = Pairing.G1Point(uint256(3586668765715950597410254704796987152938355720267175556446411938579398877187),uint256(14432509017039867508952724965857615958790373447405491556246109443582417356371));
        vk.IC[16] = Pairing.G1Point(uint256(13424955105910682329437834332256182374144039233141681163711353037902043353624),uint256(8828196912432851404620285783963445728971234847609988578064626258564419149903));
        vk.IC[17] = Pairing.G1Point(uint256(19498045024490161929290025977625871010984545864965513804637977543690052687840),uint256(3627781218554636731255925050312884159220556158857504310035324591075507341985));
        vk.IC[18] = Pairing.G1Point(uint256(6820954743825462073137691355415322375419648379697205736806101957260859392096),uint256(6822456093309154018611729069779369461010629633120666152831121563742452382068));
        vk.IC[19] = Pairing.G1Point(uint256(10146291207839686784931205706655390504982227615201916016512394454963062022103),uint256(15291925836071598839382750465570868598581701748606554458872607946281882762076));
        vk.IC[20] = Pairing.G1Point(uint256(3020571693515555142429585092076314911042032628968564084423084485307011112637),uint256(6709422867669217651487963068532056664970460705582793088794996876868156935615));

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
        for (uint256 i = 0; i < 20; i++) {
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
