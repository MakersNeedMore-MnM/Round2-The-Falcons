import { useEffect, useRef } from "react";
import type { Material, Mesh } from "three";

export function ResilienceScene({ mode = "landing" }: { mode?: "landing" | "console" }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const element = host.current;
    if (!element) return;
    let cancelled = false;
    let teardown = () => undefined;
    void import("three").then((THREE) => {
      if (cancelled) return;
      const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      const scene = new THREE.Scene();
      scene.fog = new THREE.FogExp2(0x05070a, mode === "landing" ? 0.038 : 0.055);
      const camera = new THREE.PerspectiveCamera(48, 1, .1, 150);
      camera.position.set(0, mode === "landing" ? 6 : 9, mode === "landing" ? 17 : 22);
      const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75)); renderer.setClearColor(0x05070a, 0); element.appendChild(renderer.domElement);

      const terrainGeometry = new THREE.PlaneGeometry(42, 30, 54, 38);
      const positions = terrainGeometry.attributes.position!;
      for (let i = 0; i < positions.count; i += 1) { const x = positions.getX(i); const y = positions.getY(i); positions.setZ(i, Math.sin(x * .54) * .52 + Math.cos(y * .42) * .42 + Math.sin((x + y) * .23) * .72); }
      terrainGeometry.computeVertexNormals();
      const terrain = new THREE.Mesh(terrainGeometry, new THREE.MeshBasicMaterial({ color: 0x46514b, wireframe: true, transparent: true, opacity: mode === "landing" ? .19 : .08 }));
      terrain.rotation.x = -Math.PI / 2.2; terrain.position.set(0, -5.2, -3); scene.add(terrain);

      const ringGroup = new THREE.Group();
      [4.1, 5.8, 7.5].forEach((radius, index) => { const ring = new THREE.Mesh(new THREE.TorusGeometry(radius, index === 0 ? .045 : .022, 8, 160), new THREE.MeshBasicMaterial({ color: index === 0 ? 0xe12b22 : 0x7f9188, transparent: true, opacity: index === 0 ? .82 : .25 })); ring.rotation.set(Math.PI / 2.5 + index * .12, index * .18, index * .1); ringGroup.add(ring); });
      ringGroup.position.set(mode === "landing" ? 5 : 8, mode === "landing" ? 1 : 4, -4); scene.add(ringGroup);

      const starCount = mode === "landing" ? 720 : 340; const starPositions = new Float32Array(starCount * 3);
      for (let index = 0; index < starCount; index += 1) { starPositions[index * 3] = (Math.random() - .5) * 46; starPositions[index * 3 + 1] = (Math.random() - .5) * 24; starPositions[index * 3 + 2] = (Math.random() - .5) * 34; }
      const starGeometry = new THREE.BufferGeometry(); starGeometry.setAttribute("position", new THREE.BufferAttribute(starPositions, 3));
      const stars = new THREE.Points(starGeometry, new THREE.PointsMaterial({ color: 0xcbd7d0, size: .035, transparent: true, opacity: .65, sizeAttenuation: true })); scene.add(stars);

      const nodes = new THREE.Group();
      for (let index = 0; index < 18; index += 1) { const node = new THREE.Mesh(new THREE.SphereGeometry(index % 6 === 0 ? .11 : .055, 10, 10), new THREE.MeshBasicMaterial({ color: index % 6 === 0 ? 0xff5338 : 0xb8c4bd })); const angle = index * 2.18; const radius = 2.2 + index % 5 * .72; node.position.set(Math.cos(angle) * radius + 5, Math.sin(angle * .8) * 2 + 1, -3 + Math.sin(angle) * 2.2); nodes.add(node); }
      const linkPositions: number[] = [];
      for (let index = 1; index < nodes.children.length; index += 1) { const previous = nodes.children[index - 1]!.position; const current = nodes.children[index]!.position; linkPositions.push(previous.x, previous.y, previous.z, current.x, current.y, current.z); }
      const linkGeometry = new THREE.BufferGeometry(); linkGeometry.setAttribute("position", new THREE.Float32BufferAttribute(linkPositions, 3));
      const links = new THREE.LineSegments(linkGeometry, new THREE.LineBasicMaterial({ color: 0x8ea099, transparent: true, opacity: mode === "landing" ? .18 : .08 })); nodes.add(links);
      scene.add(nodes);

      const coreGeometry = new THREE.IcosahedronGeometry(2.35, 2);
      const core = new THREE.Mesh(coreGeometry, new THREE.MeshBasicMaterial({ color: 0xe12b22, wireframe: true, transparent: true, opacity: mode === "landing" ? .11 : .045 }));
      core.position.set(mode === "landing" ? 5 : 8, mode === "landing" ? 1 : 4, -4); scene.add(core);

      const pointer = { x: 0, y: 0 }; let scroll = 0;
      const onPointer = (event: PointerEvent) => { pointer.x = event.clientX / window.innerWidth - .5; pointer.y = event.clientY / window.innerHeight - .5; };
      const onScroll = () => { scroll = Math.min(1, window.scrollY / Math.max(window.innerHeight * 4, 1)); };
      const resize = () => { const width = element.clientWidth; const height = element.clientHeight; camera.aspect = width / Math.max(height, 1); camera.updateProjectionMatrix(); renderer.setSize(width, height, false); };
      window.addEventListener("pointermove", onPointer, { passive: true }); window.addEventListener("scroll", onScroll, { passive: true }); window.addEventListener("resize", resize); resize(); onScroll();
      let frame = 0;
      const render = (time: number) => { const t = time * .00012; if (!reduced) { ringGroup.rotation.z = t + scroll * .9; nodes.rotation.y = -t * .45 - scroll * .35; core.rotation.set(t * .45, -t * .7, scroll); core.scale.setScalar(1 + Math.sin(t * 9) * .025); stars.rotation.y = t * .1 + scroll * .08; terrain.position.z = -3 + scroll * 2.5; camera.position.x += (pointer.x * 1.4 - camera.position.x) * .018; camera.position.y += ((mode === "landing" ? 6 : 9) - pointer.y * .8 + scroll * 1.2 - camera.position.y) * .018; camera.position.z += ((mode === "landing" ? 17 : 22) + scroll * 2.2 - camera.position.z) * .018; } camera.lookAt(1, scroll * .5, -4); renderer.render(scene, camera); if (!reduced) frame = requestAnimationFrame(render); };
      render(0);
      teardown = () => { cancelAnimationFrame(frame); window.removeEventListener("pointermove", onPointer); window.removeEventListener("scroll", onScroll); window.removeEventListener("resize", resize); terrainGeometry.dispose(); (terrain.material as Material).dispose(); starGeometry.dispose(); (stars.material as Material).dispose(); coreGeometry.dispose(); (core.material as Material).dispose(); ringGroup.children.forEach((child) => { const mesh = child as Mesh; mesh.geometry.dispose(); (mesh.material as Material).dispose(); }); nodes.children.forEach((child) => { const mesh = child as Mesh; mesh.geometry.dispose(); (mesh.material as Material).dispose(); }); renderer.dispose(); renderer.forceContextLoss(); renderer.domElement.remove(); };
    });
    return () => { cancelled = true; teardown(); };
  }, [mode]);
  return <div className={`resilience-scene resilience-scene--${mode}`} ref={host} aria-hidden="true" />;
}
