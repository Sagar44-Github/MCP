import { useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import type { Group, Mesh } from 'three'

function CoreModel({ reducedMotion }: { reducedMotion: boolean }) {
  const core = useRef<Group>(null)
  const orbit = useRef<Group>(null)

  useFrame((state, delta) => {
    if (reducedMotion) return
    if (core.current) {
      core.current.rotation.y += delta * 0.14
      core.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.21) * 0.08
    }
    if (orbit.current) orbit.current.rotation.z += delta * 0.06
  })

  return (
    <group>
      <group ref={core}>
        <mesh>
          <icosahedronGeometry args={[0.91, 2]} />
          <meshStandardMaterial color="#b7f38d" emissive="#4d8c45" emissiveIntensity={0.48} metalness={0.74} roughness={0.22} transparent opacity={0.76} />
        </mesh>
        <mesh scale={1.08}>
          <icosahedronGeometry args={[0.91, 1]} />
          <meshBasicMaterial color="#c3f9a0" wireframe transparent opacity={0.42} />
        </mesh>
        <mesh scale={1.34}>
          <icosahedronGeometry args={[0.91, 0]} />
          <meshBasicMaterial color="#86dca0" wireframe transparent opacity={0.16} />
        </mesh>
      </group>
      <group ref={orbit} rotation={[0.84, 0.38, -0.34]}>
        <mesh>
          <torusGeometry args={[1.46, 0.008, 8, 150]} />
          <meshBasicMaterial color="#9be6ad" transparent opacity={0.56} />
        </mesh>
        <mesh position={[1.46, 0, 0]}>
          <sphereGeometry args={[0.055, 18, 18]} />
          <meshBasicMaterial color="#d6ffb0" />
        </mesh>
      </group>
      <group rotation={[1.2, -0.52, 0.72]}>
        <mesh>
          <torusGeometry args={[1.82, 0.005, 8, 150]} />
          <meshBasicMaterial color="#78baf2" transparent opacity={0.34} />
        </mesh>
        <mesh position={[-1.82, 0, 0]}>
          <sphereGeometry args={[0.041, 16, 16]} />
          <meshBasicMaterial color="#8cc8ff" />
        </mesh>
      </group>
      <mesh position={[0.16, -0.1, 0.04]}>
        <sphereGeometry args={[0.17, 32, 32]} />
        <meshBasicMaterial color="#d8ffd2" transparent opacity={0.16} />
      </mesh>
      <pointLight position={[1.2, 1.3, 2]} color="#99ed96" intensity={1.9} distance={5} />
      <pointLight position={[-1.5, -1, -1]} color="#77aeea" intensity={1.1} distance={5} />
    </group>
  )
}

function DataPulses({ reducedMotion }: { reducedMotion: boolean }) {
  const first = useRef<Mesh>(null)
  const second = useRef<Mesh>(null)
  const third = useRef<Mesh>(null)

  useFrame((state) => {
    if (reducedMotion) return
    const time = state.clock.elapsedTime
    const refs = [first.current, second.current, third.current]
    refs.forEach((mesh, index) => {
      if (!mesh) return
      const phase = time * 0.32 + index * (Math.PI * 2 / 3)
      mesh.position.set(Math.cos(phase) * 2.07, Math.sin(phase * 0.72) * 0.2, Math.sin(phase) * 1.24)
      const pulse = 0.72 + (Math.sin(time * 2.5 + index) + 1) * 0.22
      mesh.scale.setScalar(pulse)
    })
  })

  return (
    <group>
      <mesh ref={first}><sphereGeometry args={[0.028, 12, 12]} /><meshBasicMaterial color="#c4f6a4" /></mesh>
      <mesh ref={second}><sphereGeometry args={[0.023, 12, 12]} /><meshBasicMaterial color="#92d9b0" /></mesh>
      <mesh ref={third}><sphereGeometry args={[0.021, 12, 12]} /><meshBasicMaterial color="#86b9f3" /></mesh>
    </group>
  )
}

export default function SentinelScene({ reducedMotion = false }: { reducedMotion?: boolean }) {
  return (
    <Canvas
      camera={{ position: [0, 0, 5.7], fov: 36 }}
      dpr={[1, 1.4]}
      frameloop={reducedMotion ? 'demand' : 'always'}
      gl={{ alpha: true, antialias: true, powerPreference: 'low-power' }}
      fallback={<div className="scene-canvas-fallback" aria-hidden="true"><span /></div>}
    >
      <ambientLight intensity={0.58} />
      <CoreModel reducedMotion={reducedMotion} />
      <DataPulses reducedMotion={reducedMotion} />
    </Canvas>
  )
}
