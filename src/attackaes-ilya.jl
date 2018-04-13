# This file is a Jlsca implementation of Ilya Kizhvatov's XMEGA® Attack
# license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Jonathan Beverley

using ..Aes
using ..Trs

export AesIlyaAttack

type AesIlyaAttack <: AesAttack
    mode::AesMode
    keyLength::AesKeyLength
    direction::Direction

    function AesIlyaAttack()
        return new(CIPHER, KL128, FORWARD)
    end
end

function numberOfPhases(params::AesIlyaAttack)
    return 256
end

# Need a new target
type RoundIn <: Target{UInt8,UInt8,UInt8}
    phaseInput::UInt8
end
target(a::RoundIn, data::UInt8, keyByte::UInt8) = data ⊻ keyByte ⊻ a.phaseInput
show(io::IO, a::RoundIn) = print(io, "Round input, for r0, that means plaintext ⊻ keybyte")   

# And a dummy target
type ConstTarget <: Target{UInt8,UInt8,UInt8}
    constant::UInt8
end
target(a::ConstTarget, data::UInt8, keyByte::UInt8) = a.constant
show(io::IO, a::ConstTarget) = print(io, "Returns a constant value")   

function getTargets(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    # We have 16 targets, each corresponds to a key byte
	# We have 256 phases, in each phase we generate a possible roundKey
	# getTargets() is invoked at the beginning of each phase.
	# XXX so how do we get the previous keybyte in the right place?
	# XXX can our Target carry water for us?
	# XXX maybe DataPass? 

    print("--------------------\n")
    @printf("phase: %d\n", phase)
    print(phaseInput)
    print("\n")

	ct = ConstTarget(phase-1)
	targetfn = RoundIn(42) # XXX HOW DO WE GET IT HERE?
	suffix = [targetfn for i in 1:(numberOfTargets(params,phase)-1)]
	r = vcat(ct, suffix)
	
	print(r)
    print("\n")
    @printf("fn-count: %d\n", numberOfTargets(params,phase))
    print("--------------------\n")
    return r
end

# We attack one keybyte at a time, but in 256 ways...
numberOfTargets(params::AesIlyaAttack, phase::Int) = 16

show(io::IO, a::AesIlyaAttack) = print(io, "AES two-byte Ilya attack")

function printParameters(params::AesIlyaAttack)
    @printf("mode:       %s\n", string(params.mode))
    @printf("key length: %s\n", string(params.keyLength))
    @printf("direction:  %s\n", string(params.direction))
end

function getDataPass(params::AesIlyaAttack, phase::Int, phaseInput::Vector{UInt8})
    print("--------------------\n")
    @printf("phase: %d\n", phase)
    print(phaseInput)
    print("\n")
    print("--------------------\n")
    return Nullable(x -> x[1:16])
end

