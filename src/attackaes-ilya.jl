# This file is a Jlsca implementation of Ilya Kizhvatov's XMEGA® Attack
# license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Jonathan Beverley

using ..Aes
using ..Trs

export AesIlyaAttack, ilyaRankCallBack, flipHW

type AesIlyaAttack <: AesAttack
    mode::AesMode
    keyLength::AesKeyLength
    direction::Direction

    function AesIlyaAttack()
        return new(CIPHER, KL128, FORWARD)
    end
end

previousKeyByte = -1

function ilyaRankCallBack(rankData::RankData, keyOffsets::Vector{Int64})
    global previousKeyByte
    phase = length(rankData.combinedScores)
    target = length(rankData.combinedScores[phase])
    orderedArrayOfFloats = rankData.combinedScores[phase][target]
    previousKeyByte = indmax(orderedArrayOfFloats)-1
end

type flipHW <: Leakage
end
function leak(this::flipHW, intermediate::Union{UInt8,UInt16,UInt32,UInt128})
    typeof(intermediate).size*8 - hw(intermediate)
end

function numberOfPhases(params::AesIlyaAttack)
    return 256
end

# Need a new target
type TwoRoundTarget <: Target{UInt8,UInt8,UInt8} end
function target(a::TwoRoundTarget, data::UInt8, guess::UInt8)
    global previousKeyByte
    data ⊻ guess ⊻ previousKeyByte
end
show(io::IO, a::TwoRoundTarget) = print(io, "Round input, for r0, that means plaintext ⊻ keybyte")   

function getTargets(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    global previousKeyByte
    # We know the key, it is the following, but we don't cheat, so not using it.
    # 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    previousKeyByte = phase
    # We can't set previous key-bytes yet, because we don't know them, do that later
    targetfn = TwoRoundTarget()
    return [targetfn for i in 1:(numberOfTargets(params,phase))]
end

# We attack one keybyte at a time, but in 256 ways...
numberOfTargets(params::AesIlyaAttack, phase::Int) = 15

# However, we skip the first byte...
function getTargetOffsets(params::AesIlyaAttack, phase::Int)
    [i for i in 1:15]
end

show(io::IO, a::AesIlyaAttack) = print(io, "AES two-byte Ilya attack")

function printParameters(params::AesIlyaAttack)
    @printf("mode:       %s\n", string(params.mode))
    @printf("key length: %s\n", string(params.keyLength))
    @printf("direction:  %s\n", string(params.direction))
end

function datafilter(data::Vector{UInt8})
    # called once per row, to return the "data" we'll use...
    # we return pairs of xor'd bytes to prep for above...
    return [ data[i]⊻data[i+1] for i in 1:(length(data)-1)]
end

function getDataPass(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    return Nullable(x -> datafilter(x))
end

