(function () {
    'use strict';

    let scene, camera, renderer, upperArch, lowerArch, upperAligner, lowerAligner;
    let isPlaying = false;
    let currentStep = 1;
    let totalSteps = 22;
    let playInterval = null;
    let showAligner = true;
    let animFrameId = null;

    function getCaseIdFromPath() {
        const match = window.location.pathname.match(/\/simulation\/([^/]+)/);
        if (match && match[1]) return decodeURIComponent(match[1]);
        const qs = new URLSearchParams(window.location.search);
        return qs.get('case_id') || '1';
    }

    function setText(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    function renderIprRows(contacts) {
        const list = document.getElementById('ipr-rows-container');
        if (!list) return;
        list.textContent = '';
        if (!Array.isArray(contacts) || contacts.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'ipr-mini-row';
            empty.textContent = 'No IPR reduction contacts scheduled.';
            list.appendChild(empty);
            setText('ipr-total-badge', '0.00mm Total');
            return;
        }
        let sumMm = 0;
        for (const c of contacts) {
            const w = Number(c.width_mm) || 0;
            sumMm += w;
            const row = document.createElement('div');
            row.className = 'ipr-mini-row';

            const left = document.createElement('span');
            const strong = document.createElement('strong');
            strong.textContent = String(c.pair || '—');
            left.appendChild(strong);

            const mid = document.createElement('span');
            mid.className = 'ipr-badge-mini';
            mid.textContent = `${w.toFixed(2)} mm`;

            const right = document.createElement('span');
            right.className = 'ipr-timing-mini';
            right.textContent = c.after_step ? `After Step ${String(c.after_step).padStart(2, '0')}` : 'As prescribed';

            row.appendChild(left);
            row.appendChild(mid);
            row.appendChild(right);
            list.appendChild(row);
        }
        setText('ipr-total-badge', `${sumMm.toFixed(2)}mm Total`);
    }

    async function loadCaseData() {
        const caseId = getCaseIdFromPath();
        const backLink = document.getElementById('back-to-case-link');
        if (backLink) backLink.href = `/cases/${encodeURIComponent(caseId)}/view`;

        const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}`, {
            credentials: 'include',
            headers: { 'Accept': 'application/json' }
        });
        if (res.status === 401) {
            window.location.replace('/login');
            return null;
        }
        if (!res.ok) {
            const container = document.getElementById('webgl-container');
            if (container) {
                container.textContent = '';
                const msg = document.createElement('div');
                msg.style.cssText = 'display:flex;align-items:center;justify-content:center;height:100%;color:#e2e8f0;font-size:16px;';
                msg.textContent = 'Case not found or access denied.';
                container.appendChild(msg);
            }
            return null;
        }
        const json = await res.json();
        const c = json && json.data ? json.data : null;
        if (!c) return null;

        if (backLink) backLink.href = `/cases/${encodeURIComponent(c.id)}/view`;
        document.title = `VelourCare 3D Aligner Simulation | ${c.case_id || c.id}`;
        setText('viewer-setup-badge', `3D Digital Setup #${c.id}`);
        setText('meta-patient', c.patient_name || '—');
        setText('meta-case-id', c.case_id || String(c.id));
        setText('meta-doctor', c.doctor_name || '—');
        const upper = Number(c.upper_aligners) || 1;
        const lower = Number(c.lower_aligners) || 1;
        totalSteps = Math.max(upper, lower, 1);
        setText('meta-prescription', `${c.upper_aligners || 0} Upper / ${c.lower_aligners || 0} Lower`);

        const slider = document.getElementById('stageSlider');
        if (slider) {
            slider.max = String(totalSteps);
            slider.value = '1';
        }
        setText('stageLabel', `Stage 01 / ${String(totalSteps).padStart(2, '0')}`);

        const plans = Array.isArray(c.treatment_plans) ? c.treatment_plans : [];
        const contacts = plans[0]?.plan_document_data?.ipr_contacts || [];
        renderIprRows(contacts);
        return c;
    }

    function createTooth(x, y, z, rotY, scaleY) {
        const group = new THREE.Group();
        const crownGeo = new THREE.CylinderGeometry(0.7, 0.85, 1.8 * scaleY, 16);
        const enamelMat = new THREE.MeshPhongMaterial({ color: 0xf4f3ec, specular: 0x666666, shininess: 90 });
        group.add(new THREE.Mesh(crownGeo, enamelMat));

        const attGeo = new THREE.BoxGeometry(0.3, 0.5, 0.25);
        const attMat = new THREE.MeshPhongMaterial({ color: 0x0ab39c, shininess: 80 });
        const attachment = new THREE.Mesh(attGeo, attMat);
        attachment.position.set(0, 0, 0.85);
        group.add(attachment);

        group.position.set(x, y, z);
        group.rotation.y = rotY;
        return group;
    }

    function buildDentalArches() {
        upperArch = new THREE.Group();
        lowerArch = new THREE.Group();
        const numTeeth = 14;
        for (let i = 0; i < numTeeth; i++) {
            const angle = (i / (numTeeth - 1)) * Math.PI;
            const x = -Math.cos(angle) * 6.2;
            const z = -Math.sin(angle) * 6.8 + 2.5;
            const rotY = angle - Math.PI / 2;
            upperArch.add(createTooth(x, 1.4, z, rotY, 1.1));
            lowerArch.add(createTooth(x * 0.94, -1.4, z * 0.94, rotY, 0.95));
        }

        const alignerMat = new THREE.MeshPhysicalMaterial({
            color: 0x85e3ff, transparent: true, opacity: 0.35, roughness: 0.1, transmission: 0.8, ior: 1.45
        });
        upperAligner = new THREE.Mesh(new THREE.TorusGeometry(6.4, 0.9, 12, 32, Math.PI), alignerMat);
        upperAligner.rotation.x = Math.PI / 2;
        upperAligner.position.set(0, 1.4, 2.5);
        upperArch.add(upperAligner);

        lowerAligner = new THREE.Mesh(new THREE.TorusGeometry(6.0, 0.85, 12, 32, Math.PI), alignerMat);
        lowerAligner.rotation.x = Math.PI / 2;
        lowerAligner.position.set(0, -1.4, 2.5);
        lowerArch.add(lowerAligner);

        scene.add(upperArch);
        scene.add(lowerArch);
    }

    function applyStageMorph(step) {
        if (!upperArch || !lowerArch) return;
        const factor = step / totalSteps;
        upperArch.children.forEach((t, idx) => {
            if (t.isGroup) {
                const crowdOffset = Math.sin(idx * 1.5) * (1 - factor) * 0.35;
                t.position.y = 1.4 + crowdOffset * 0.2;
                t.rotation.z = crowdOffset * 0.4;
            }
        });
        lowerArch.children.forEach((t, idx) => {
            if (t.isGroup) {
                const crowdOffset = Math.cos(idx * 1.5) * (1 - factor) * 0.3;
                t.position.y = -1.4 - crowdOffset * 0.2;
                t.rotation.z = -crowdOffset * 0.3;
            }
        });
    }

    function onSliderChange(val) {
        currentStep = parseInt(val, 10) || 1;
        setText('stageLabel', `Stage ${String(currentStep).padStart(2, '0')} / ${String(totalSteps).padStart(2, '0')}`);
        applyStageMorph(currentStep);
    }

    function togglePlay() {
        isPlaying = !isPlaying;
        setText('playIcon', isPlaying ? '❚❚' : '▶');
        if (isPlaying) {
            playInterval = setInterval(() => {
                currentStep = currentStep >= totalSteps ? 1 : currentStep + 1;
                const slider = document.getElementById('stageSlider');
                if (slider) slider.value = String(currentStep);
                onSliderChange(currentStep);
            }, 400);
        } else if (playInterval) {
            clearInterval(playInterval);
            playInterval = null;
        }
    }

    function setView(angle, targetBtn) {
        document.querySelectorAll('.preset-btn[data-view]').forEach(b => b.classList.remove('active'));
        if (targetBtn) targetBtn.classList.add('active');
        if (!scene || !camera) return;
        if (angle === 'front') { scene.rotation.set(0, 0, 0); camera.position.set(0, 0, 26); }
        else if (angle === 'upper') { scene.rotation.set(Math.PI / 2.2, 0, 0); camera.position.set(0, 15, 20); }
        else if (angle === 'lower') { scene.rotation.set(-Math.PI / 2.2, 0, 0); camera.position.set(0, -15, 20); }
        else if (angle === 'right') { scene.rotation.set(0, -Math.PI / 2.5, 0); camera.position.set(15, 0, 22); }
        else if (angle === 'left') { scene.rotation.set(0, Math.PI / 2.5, 0); camera.position.set(-15, 0, 22); }
    }

    function animate() {
        if (document.hidden) {
            animFrameId = null;
            return;
        }
        animFrameId = requestAnimationFrame(animate);
        if (renderer && scene && camera) renderer.render(scene, camera);
    }

    async function init() {
        const loaded = await loadCaseData();
        if (!loaded) return;

        const container = document.getElementById('webgl-container');
        if (typeof THREE === 'undefined') {
            if (container) {
                container.textContent = '';
                const wrap = document.createElement('div');
                wrap.style.cssText = 'display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#fff;text-align:center;padding:24px;';
                const h3 = document.createElement('h3');
                h3.textContent = '3D Simulation Offline Mode';
                const p = document.createElement('p');
                p.style.cssText = 'color:#a0aec0;max-width:440px;font-size:14px;';
                p.textContent = 'The Three.js 3D rendering library could not be loaded. Verify connectivity to stream WebGL aligner animation.';
                wrap.appendChild(h3);
                wrap.appendChild(p);
                container.appendChild(wrap);
            }
            return;
        }

        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x111420);
        camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 1000);
        camera.position.set(0, 5, 28);

        renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        renderer.shadowMap.enabled = true;
        container.appendChild(renderer.domElement);

        scene.add(new THREE.AmbientLight(0xffffff, 0.7));
        const d1 = new THREE.DirectionalLight(0xffffff, 0.8);
        d1.position.set(10, 20, 15);
        scene.add(d1);
        const d2 = new THREE.DirectionalLight(0x0ab39c, 0.3);
        d2.position.set(-10, -10, -10);
        scene.add(d2);

        buildDentalArches();

        let isDragging = false;
        let prevX = 0;
        let prevY = 0;
        container.addEventListener('mousedown', e => { isDragging = true; prevX = e.clientX; prevY = e.clientY; });
        window.addEventListener('mouseup', () => { isDragging = false; });
        window.addEventListener('mousemove', e => {
            if (!isDragging) return;
            scene.rotation.y += (e.clientX - prevX) * 0.008;
            scene.rotation.x += (e.clientY - prevY) * 0.008;
            prevX = e.clientX;
            prevY = e.clientY;
        });
        window.addEventListener('wheel', e => {
            camera.position.z = Math.max(10, Math.min(60, camera.position.z + e.deltaY * 0.02));
        });
        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        animate();
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.preset-btn[data-view]').forEach(btn => {
            btn.addEventListener('click', evt => setView(btn.dataset.view, evt.currentTarget));
        });
        const toggleBtn = document.getElementById('toggleAlignerBtn');
        if (toggleBtn) toggleBtn.addEventListener('click', () => {
            showAligner = !showAligner;
            if (upperAligner) upperAligner.visible = showAligner;
            if (lowerAligner) lowerAligner.visible = showAligner;
        });
        const playBtn = document.getElementById('playBtn');
        if (playBtn) playBtn.addEventListener('click', togglePlay);
        const prevBtn = document.getElementById('prevStepBtn');
        if (prevBtn) prevBtn.addEventListener('click', () => {
            currentStep = Math.max(1, currentStep - 1);
            const slider = document.getElementById('stageSlider');
            if (slider) slider.value = String(currentStep);
            onSliderChange(currentStep);
        });
        const nextBtn = document.getElementById('nextStepBtn');
        if (nextBtn) nextBtn.addEventListener('click', () => {
            currentStep = Math.min(totalSteps, currentStep + 1);
            const slider = document.getElementById('stageSlider');
            if (slider) slider.value = String(currentStep);
            onSliderChange(currentStep);
        });
        const resetBtn = document.getElementById('resetRotationBtn');
        if (resetBtn) resetBtn.addEventListener('click', () => {
            if (scene && camera) {
                scene.rotation.set(0, 0, 0);
                camera.position.set(0, 5, 28);
            }
        });
        const slider = document.getElementById('stageSlider');
        if (slider) slider.addEventListener('input', e => onSliderChange(e.target.value));

        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && !animFrameId && renderer && scene && camera) {
                animate();
            }
        });
        window.addEventListener('beforeunload', () => {
            if (playInterval) clearInterval(playInterval);
            if (animFrameId) cancelAnimationFrame(animFrameId);
        });

        init();
    });
})();
