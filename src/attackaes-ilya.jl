# This file is a Jlsca implementation of Ilya Kizhvatov's XMEGA® Attack
# license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Jonathan Beverley

using ..Aes
using ..Trs

export AesIlyaAttack, ilyaRankCallBack, flipHW, ProgressiveGlobalMaximization

type AesIlyaAttack <: AesAttack
    mode::AesMode
    keyLength::AesKeyLength
    direction::Direction
    sbox::Vector{UInt8}
    function AesIlyaAttack()
        return new(CIPHER, KL128, FORWARD, Aes.sbox)
    end
end

previousKeyByte = 0x00::UInt8
previousIndex = 0
knownKey = hex2bytes("")

function ilyaRankCallBack(rankData::RankData, keyOffsets::Vector{Int64})
    global previousKeyByte, previousIndex, knownKey
    phase = length(rankData.combinedScores)
    target = length(rankData.combinedScores[phase])
    orderedArrayOfFloats = rankData.combinedScores[phase][target]
    maxindex = indmax(orderedArrayOfFloats)
    if (target <= length(knownKey))
        previousKeyByte = knownKey[target]
    else
        previousKeyByte = UInt8(maxindex-1)
    end
    @printf("Using previous key-byte: %02x\n", previousKeyByte)
    previousIndex = rankData.offsets[phase][target][1][maxindex]
end

type flipHW <: Leakage end
function leak(this::flipHW, intermediate::Union{UInt8,UInt16,UInt32,UInt128})
    return typeof(intermediate).size*8 - hw(intermediate)
end

# Need a new target
type TwoRoundTarget <: Target{UInt16,UInt8,UInt8} end
function target(a::TwoRoundTarget, data::UInt16, guess::UInt8)
    global previousKeyByte
    prevData = UInt8(data>>8)
    nowData = UInt8(data&0xff)
    return (prevData ⊻ previousKeyByte) ⊻ (nowData ⊻ guess)
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
    return vcat(
            [UInt16(data[1])],
            [UInt16(data[i-1])<<8|data[i] for i in 2:(length(data))]
           )
end

function getDataPass(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    return Nullable(x -> datafilter(x))
end

type ProgressiveGlobalMaximization <: Maximization end
show(io::IO, a::ProgressiveGlobalMaximization) = print(io, "progressive global max")

function update!(g::ProgressiveGlobalMaximization, a::RankData, phase::Int, C::AbstractArray{Float64,2}, target::Int, leakage::Int, nrConsumedRows::Int, nrConsumedCols::Int,  nrRows::Int, nrCols::Int, colOffset::Int)
    global previousIndex
    # C is a matrix of the correlation between guesses and samples
    # so if we are checking 21 samples, we get a matrix[21][256]
    (samples,guesses) = size(C)
    r = lazyinit(a,phase,target,guesses,leakage,nrConsumedRows,nrConsumedCols,nrRows,nrCols)
    #print("pre-C: ",C,"\n")
    for i in 1:(previousIndex)
        for j in 1:256
            C[i,j] = 0.0
        end
    end
    #print("post-C: ",C,"\n")

    (corrvals, corrvaloffsets) = findmax(C, 1)

    for (idx,val) in enumerate(corrvals)
        if val > a.scores[phase][target][leakage][idx,r]
            a.scores[phase][target][leakage][idx,r] = val
            a.offsets[phase][target][leakage][idx,r] = ind2sub(size(C), corrvaloffsets[idx])[1] + colOffset-1
        end
    end
end

