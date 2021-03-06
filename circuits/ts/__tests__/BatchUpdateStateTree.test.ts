jest.setTimeout(1200000)
import { 
    executeCircuit,
    getSignalByName,
    compileAndLoadCircuit
} from '../'
import { config } from 'maci-config'
import { MaciState } from 'maci-core'

import {
    Keypair,
    StateLeaf,
    Command,
    Message,
} from 'maci-domainobjs'

import {
    genRandomSalt,
} from 'maci-crypto'


const batchSize = config.maci.messageBatchSize
const stateTreeDepth = config.maci.merkleTrees.stateTreeDepth
const messageTreeDepth = config.maci.merkleTrees.messageTreeDepth
const voteOptionTreeDepth = config.maci.merkleTrees.voteOptionTreeDepth
const voteOptionsMaxIndex = config.maci.voteOptionsMaxLeafIndex
const initialVoiceCreditBalance = config.maci.initialVoiceCreditBalance

// Set up keypairs
const user = new Keypair()
const coordinator = new Keypair()

describe('State tree root update verification circuit', () => {
    let circuit 
    const voteWeight = BigInt(2)

    beforeAll(async () => {
        circuit = await compileAndLoadCircuit(
            config.env === 'test' ?
                'test/batchUpdateStateTree_test.circom'
                :
                'prod/batchUpdateStateTree_small.circom'
        )
    })

    it('BatchUpdateStateTree should produce the correct state root from a partially filled batch', async () => {
        const maciState = new MaciState(
            coordinator,
            stateTreeDepth,
            messageTreeDepth,
            voteOptionTreeDepth,
            voteOptionsMaxIndex,
        )

        // Sign up the user
        maciState.signUp(user.pubKey, initialVoiceCreditBalance)

        const stateRootBefore = maciState.genStateRoot()

        const command = new Command(
            BigInt(1),
            user.pubKey,
            BigInt(0),
            voteWeight,
            BigInt(1),
            genRandomSalt(),
        )
        const signature = command.sign(user.privKey)
        const sharedKey = Keypair.genEcdhSharedKey(user.privKey, coordinator.pubKey)
        const message = command.encrypt(signature, sharedKey)

        maciState.publishMessage(message, user.pubKey)

        const randomStateLeaf = StateLeaf.genRandomLeaf()

        // Generate circuit inputs
        const circuitInputs = 
            maciState.genBatchUpdateStateTreeCircuitInputs(
                0,
                batchSize,
                randomStateLeaf,
            )

        // Calculate the witness
        const witness = await executeCircuit(circuit, circuitInputs)

        // Get the circuit-generated root
        const circuitNewStateRoot = getSignalByName(circuit, witness, 'main.root').toString()

        // Process the batch of messages
        maciState.batchProcessMessage(
            0,
            batchSize,
            randomStateLeaf,
        )

        const stateRootAfter = maciState.genStateRoot()

        expect(stateRootBefore.toString()).not.toEqual(stateRootAfter)

        // After we run process the message via maciState.processMessage(),
        // the root generated by the circuit should match
        expect(circuitNewStateRoot.toString()).toEqual(stateRootAfter.toString())
    })

    it('BatchUpdateStateTree should produce the correct state root from a full batch', async () => {
        const randomStateLeaf = StateLeaf.genRandomLeaf()

        const maciState = new MaciState(
            coordinator,
            stateTreeDepth,
            messageTreeDepth,
            voteOptionTreeDepth,
            voteOptionsMaxIndex,
        )

        // Sign up the user
        maciState.signUp(user.pubKey, initialVoiceCreditBalance)

        const stateRootBefore = maciState.genStateRoot()

        // Generate a batch of valid messages from the same user. Only one of
        // these messages is valid.
        const messages: Message[] = []

        for (let i = 0; i < batchSize - 1; i++) {
            const voteWeight = BigInt(i + 1)
            const command = new Command(
                BigInt(1),
                user.pubKey,
                BigInt(0),
                voteWeight,
                BigInt(i + 1),
                genRandomSalt(),
            )
            const signature = command.sign(user.privKey)
            const sharedKey = Keypair.genEcdhSharedKey(user.privKey, coordinator.pubKey)
            const message = command.encrypt(signature, sharedKey)

            messages.push(message)

            maciState.publishMessage(message, user.pubKey)
        }

        // nonce:voteWeight in messages [ m0: 1, m1: 2, m2: 3, m3: 4 ]
        // in regular order, only m3 is valid
        // if processed in reverse order, only m0 is valid

        const copiedState = maciState.copy()
        copiedState.batchProcessMessage(
            0,
            batchSize,
            randomStateLeaf,
        )

        expect(copiedState.users[0].voiceCreditBalance.toString())
            .toEqual((initialVoiceCreditBalance - 1).toString())
        console.log(copiedState.genStateRoot())

        // Generate circuit inputs
        const circuitInputs = 
            maciState.genBatchUpdateStateTreeCircuitInputs(
                0,
                batchSize,
                randomStateLeaf,
            )

        // Calculate the witness
        const witness = await executeCircuit(circuit, circuitInputs)

        // Get the circuit-generated root
        const circuitNewStateRoot = getSignalByName(circuit, witness, 'main.root').toString()

        // Process the batch of messages
        maciState.batchProcessMessage(
            0,
            batchSize,
            randomStateLeaf,
        )

        const stateRootAfter = maciState.genStateRoot()

        expect(stateRootBefore.toString()).not.toEqual(stateRootAfter)

        // After we run process the message via maciState.processMessage(),
        // the root generated by the circuit should match
        expect(circuitNewStateRoot.toString()).toEqual(stateRootAfter.toString())
    })

    it('BatchUpdateStateTree should produce the correct state root from one and a half batches', async () => {
        const randomStateLeaf = StateLeaf.genRandomLeaf()

        const maciState = new MaciState(
            coordinator,
            stateTreeDepth,
            messageTreeDepth,
            voteOptionTreeDepth,
            voteOptionsMaxIndex,
        )

        // Sign up the user
        maciState.signUp(user.pubKey, initialVoiceCreditBalance)

        const stateRootBefore = maciState.genStateRoot()

        // Generate a batch of valid messages from the same user. Only one of
        // these messages is valid.
        const messages: Message[] = []

        for (let i = 0; i < batchSize + Math.floor(batchSize / 2); i++) {
            const voteWeight = BigInt(i + 1)
            const command = new Command(
                BigInt(1),
                user.pubKey,
                BigInt(0),
                voteWeight,
                BigInt(i + 1),
                genRandomSalt(),
            )
            const signature = command.sign(user.privKey)
            const sharedKey = Keypair.genEcdhSharedKey(user.privKey, coordinator.pubKey)
            const message = command.encrypt(signature, sharedKey)

            messages.push(message)

            maciState.publishMessage(message, user.pubKey)
        }

        let numAssertions = 0

        const x = Math.floor(maciState.messages.length / batchSize) 
        for (let i = x * batchSize; i >= 0; i -= batchSize) {
            const circuitInputs = 
                maciState.genBatchUpdateStateTreeCircuitInputs(
                    i,
                    batchSize,
                    randomStateLeaf,
                )

            // Calculate the witness
            const witness = await executeCircuit(circuit, circuitInputs)

            // Get the circuit-generated root
            const circuitNewStateRoot = getSignalByName(circuit, witness, 'main.root').toString()

            // Process the batch of messages
            maciState.batchProcessMessage(
                i,
                batchSize,
                randomStateLeaf,
            )
            const stateRootAfter = maciState.genStateRoot()

            expect(stateRootBefore.toString()).not.toEqual(stateRootAfter)
            expect(circuitNewStateRoot.toString()).toEqual(stateRootAfter.toString())
            numAssertions += 2
        }

        expect.assertions(numAssertions)
    })
})
