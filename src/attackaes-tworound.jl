# This file is a Jlsca implementation of Dr. Ilya Kizhvatov's XMEGA® Attack
# It was inspired by the ChipWhisperer Tutorial A6
# https://wiki.newae.com/Tutorial_A6_Replication_of_Ilya_Kizhvatov%27s_XMEGA%C2%AE_Attack
# As stated there, you will need a copy of the paper entitled "Side Channel
# Analysis of AVR XMEGA Crypto Engine"

# The `xor` parameter controls whether we xor with the previousKeyByte, or not.
# If we do, then (assuming the first keybyte is correct) we will get the whole
# correct key. If we do not set it, the output will be the xors of keybyte
# pairs.
#
# The `rhme3` parameter controls which pair of keybytes are xored together. In
# Ilya's paper, the keybytes are processed in linear order, but in the XMEGA
# A3U and A4U processors, they are processed in ShiftRows order.

# license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
# Author: Jonathan Beverley

using ..Aes
using ..Trs

export AesTwoRoundAttack, twoRoundRankCallBack, flipHW

type AesTwoRoundAttack <: AesAttack
    mode::AesMode
    keyLength::AesKeyLength
    direction::Direction
    xor::Bool
    sbox::Vector{UInt8}
    knownKey::Array{UInt8,1}
    previousKeyByte # untyped to allow use of `nothing`
    rhme3::Bool
    function AesTwoRoundAttack()
        return new(CIPHER, KL128, FORWARD, false, Aes.sbox, [], 0, false)
    end
end

function twoRoundRankCallBack(params::AesTwoRoundAttack, rankData::RankData, keyOffsets::Vector{Int64})
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
    params::AesTwoRoundAttack
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

function getTargets(params::AesTwoRoundAttack, phase::Int64, phaseInput::Array{UInt8,1}) 
    params.previousKeyByte = UInt8(phase-1)

    # We can't set previous key-bytes yet, because we don't know them, do that later
    targetfn = TwoRoundTarget(params)
    return [targetfn for i in 1:(numberOfTargets(params,phase))]
end

# Optional, ideally it should just work, but we might have to brute-force the first byte
numberOfPhases(params::AesTwoRoundAttack) = 1
numberOfTargets(params::AesTwoRoundAttack, phase::Int) = 16

show(io::IO, a::AesTwoRoundAttack) = print(io, "AES two-round attack")

function printParameters(params::AesTwoRoundAttack)
    @printf("mode:       %s\n", string(params.mode))
    @printf("key length: %s\n", string(params.keyLength))
    @printf("direction:  %s\n", string(params.direction))
    @printf("known key:  %s\n", string(params.knownKey))
end

function recoverKey(params::AesTwoRoundAttack, phaseInputOrig::Vector{UInt8})
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

function twoRoundFilter(params::AesTwoRoundAttack, data::Vector{UInt8})
    # Called once per row, to return the "data" we'll use...
    # We return pairs of xored bytes to prep for above...
    # For the first round, assume 0x0 as the previous datum
    if params.rhme3
        data = reshape(Aes.ShiftRows(reshape(data[1:16],(4,4))), 16)
    end
    return vcat(
                [UInt16(data[1])],
                [(UInt16(data[i-1])<<8)|data[i] for i in 2:16]
               )
end

function getDataPass(params::AesTwoRoundAttack, phase::Int, phaseInput::Vector{UInt8})
    return Nullable(x -> twoRoundFilter(params, x))
end

