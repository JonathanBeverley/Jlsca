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

previousKeyByte = 0x00::UInt8

function ilyaRankCallBack(rankData::RankData, keyOffsets::Vector{Int64})
    global previousKeyByte
    phase = length(rankData.combinedScores)
    target = length(rankData.combinedScores[phase])
    orderedArrayOfFloats = rankData.combinedScores[phase][target]
    maxindex = indmax(orderedArrayOfFloats)-1
    previousKeyByte = convert(UInt8, maxindex)
end

type flipHW <: Leakage end
function leak(this::flipHW, intermediate::Union{UInt8,UInt16,UInt32,UInt128})
    return typeof(intermediate).size*8 - hw(intermediate)
end

# Need a new target
type TwoRoundTarget <: Target{UInt8,UInt8,UInt8} end
function target(a::TwoRoundTarget, data::UInt8, guess::UInt8)
    global previousKeyByte
    return data ⊻ guess ⊻ previousKeyByte
end
show(io::IO, a::TwoRoundTarget) = print(io, "Two-round target: (Pᵢ₋₁ ⊻ Kᵢ₋₁) ⊻ (Pᵢ ⊻ Kᵢ)")

function getTargets(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    global previousKeyByte
    previousKeyByte = 0x00::UInt8

    # We can't set previous key-bytes yet, because we don't know them, do that later
    targetfn = TwoRoundTarget()
    return [targetfn for i in 1:(numberOfTargets(params,phase))]
end

# We attack one keybyte at a time, but in 256 ways...
numberOfTargets(params::AesIlyaAttack, phase::Int) = 16

show(io::IO, a::AesIlyaAttack) = print(io, "AES two-byte Ilya attack")

function printParameters(params::AesIlyaAttack)
    @printf("mode:       %s\n", string(params.mode))
    @printf("key length: %s\n", string(params.keyLength))
    @printf("direction:  %s\n", string(params.direction))
end

function datafilter(data::Vector{UInt8})
    # called once per row, to return the "data" we'll use...
    # we return pairs of xor'd bytes to prep for above...
    # For the first round, use 0x0 as the previous datum
    return vcat([data[1]], [ data[i-1]⊻data[i] for i in 2:(length(data))])
end

function getDataPass(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    return Nullable(x -> datafilter(x))
end

