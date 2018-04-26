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
    xor::Bool
    sbox::Vector{UInt8}
    knownKey::Array{UInt8,1}
    previousKeyByte # untyped to allow use of `nothing`
    rhme3::Bool
    function AesIlyaAttack()
        return new(CIPHER, KL128, FORWARD, false, Aes.sbox, [], 0, false)
    end
end

function ilyaRankCallBack(params::AesIlyaAttack, rankData::RankData, keyOffsets::Vector{Int64})
    phase = length(rankData.combinedScores)
    target = length(rankData.combinedScores[phase])
    orderedArrayOfFloats = rankData.combinedScores[phase][target]
    maxindex = indmax(orderedArrayOfFloats)
    if (target <= length(params.knownKey))
        params.previousKeyByte = params.knownKey[target]
        @printf("Using known key-byte: %02x\n", params.previousKeyByte)
    else
        params.previousKeyByte = UInt8(maxindex-1)
    end
end

type flipHW <: Leakage end
function leak(this::flipHW, intermediate::Union{UInt8,UInt16,UInt32,UInt128})
    return typeof(intermediate).size*8 - hw(intermediate)
end

# Need a new target
type TwoRoundTarget <: Target{UInt16,UInt8,UInt8}
    params::AesIlyaAttack
end
function target(a::TwoRoundTarget, data::UInt16, guess::UInt8)
    prevData = UInt8(data>>8)
    nowData = UInt8(data&0xff)
    if a.params.previousKeyByte == nothing
        return 0xff ⊻ a.params.sbox[(nowData ⊻ guess)+1]
    elseif a.params.xor
        return (nowData ⊻ guess) ⊻ (prevData ⊻ a.params.previousKeyByte)
    else
        return (nowData ⊻ guess) ⊻ (prevData)
    end
end
show(io::IO, a::TwoRoundTarget) = print(io, "Two-round target: (Pᵢ₋₁ ⊻ Kᵢ₋₁) ⊻ (Pᵢ ⊻ Kᵢ)")

function getTargets(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    if params.rhme3
        params.previousKeyByte = nothing
    else
        params.previousKeyByte = UInt8(phase-1)
    end

    # We can't set previous key-bytes yet, because we don't know them, do that later
    targetfn = TwoRoundTarget(params)
    return [targetfn for i in 1:(numberOfTargets(params,phase))]
end

# Optional, ideally it should just work, but we might have to brute-force the first byte
numberOfPhases(params::AesIlyaAttack) = 1
numberOfTargets(params::AesIlyaAttack, phase::Int) = 16

show(io::IO, a::AesIlyaAttack) = print(io, "AES two-byte Ilya attack")

function printParameters(params::AesIlyaAttack)
    @printf("mode:       %s\n", string(params.mode))
    @printf("key length: %s\n", string(params.keyLength))
    @printf("direction:  %s\n", string(params.direction))
    @printf("known key:  %s\n", string(params.knownKey))
end

function recoverKey(params::AesIlyaAttack, phaseInputOrig::Vector{UInt8})
    if params.rhme3
        result = reshape(Aes.InvShiftRows(reshape(phaseInputOrig[1:16],(4,4))), 16)
    else
        result = phaseInputOrig
    end
    for i in 1:min(length(result),length(params.knownKey))
        result[i] = params.knownKey[i]
    end
    return result
end

function twoRoundFilter(params::AesIlyaAttack, data::Vector{UInt8})
    # called once per row, to return the "data" we'll use...
    # we return pairs of xor'd bytes to prep for above...
    # For the first round, use 0x0 as the previous datum
    if params.rhme3
        data = reshape(Aes.ShiftRows(reshape(data[1:16],(4,4))), 16)
    end
    return vcat(
                [UInt16(data[1])],
                [(UInt16(data[i-1])<<8)|data[i] for i in 2:16]
               )
end

function getDataPass(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    return Nullable(x -> twoRoundFilter(params, x))
end

