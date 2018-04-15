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

numberOfPhases(params::AesIlyaAttack) = 256

# Need a new target
type TwoRoundTarget <: Target{UInt8,UInt8,UInt8} end
function target(a::TwoRoundTarget, data::UInt8, guess::UInt8)
    global previousKeyByte
    data ⊻ guess ⊻ previousKeyByte
end
show(io::IO, a::TwoRoundTarget) = print(io, "Round input, for r0, that means plaintext ⊻ keybyte")   

function getTargets(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    global previousKeyByte
    # We know the example key, it is the following, but there's no point in cheating.
    # 2b7e151628aed2a6abf7158809cf4f3c

	# Phase is 1-based, but keyBytes are 0-based
    previousKeyByte = phase - 1

    # We can't set previous key-bytes yet, because we don't know them, do that later
    targetfn = TwoRoundTarget()
    return [targetfn for i in 1:(numberOfTargets(params,phase))]
end

# We attack one keybyte at a time, but in 256 ways...
numberOfTargets(params::AesIlyaAttack, phase::Int) = 15

# However, we skip the first byte...
function getTargetOffsets(params::AesIlyaAttack, phase::Int)
    [i for i in 2:16]
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
    return [ data[i-1]⊻data[i] for i in 2:(length(data))]
end

function getDataPass(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    return Nullable(x -> datafilter(x))
end

