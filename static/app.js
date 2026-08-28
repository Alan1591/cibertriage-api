// Navegación fluida de pestañas
function cambiarPestana(tabId, btnId) {
    const tabs = ['content-consultas', 'content-denuncia', 'content-policial', 'content-judicial'];
    const btns = ['btn-v1', 'btn-v2', 'btn-v3', 'btn-v4'];

    tabs.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.style.display = 'none';
            el.classList.remove('show', 'active');
        }
    });

    btns.forEach(id => {
        const btn = document.getElementById(id);
        if (btn) btn.classList.remove('active');
    });

    const targetTab = document.getElementById(tabId);
    const targetBtn = document.getElementById(btnId);

    if (targetTab) {
        targetTab.style.display = 'block';
        targetTab.classList.add('show', 'active');
    }
    if (targetBtn) {
        targetBtn.classList.add('active');
    }
}

// Inicialización segura cuando el DOM está listo
document.addEventListener('DOMContentLoaded', () => {
    // Inicializar mapa solo si existe el contenedor y Leaflet está cargado
    if (typeof L !== 'undefined' && document.getElementById('mapa')) {
        try {
            const map = L.map('mapa').setView([-31.7317, -60.5175], 12);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: 'OpenStreetMap'
            }).addTo(map);
            
            L.marker([-31.7317, -60.5175])
                .addTo(map)
                .bindPopup('<b>Centro de Control</b><br>Paraná, Entre Ríos');
        } catch (e) {
            console.log('Mapa no cargado:', e);
        }
    }

    // Listener para el formulario de denuncia
    const form = document.getElementById('formDenuncia');
    if (form) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            alert('¡Denuncia enviada correctamente! Registrada en el sistema.');
            form.reset();
        });
    }
});

// Funciones para botones de alerta y tablas
function consultarDato() {
    const input = document.getElementById('inputConsulta');
    const resDiv = document.getElementById('resultadoConsulta');
    if (!input || !input.value.trim()) {
        alert('Ingrese un CBU, Alias, Teléfono o URL para consultar.');
        return;
    }
    if (resDiv) {
        resDiv.style.display = 'block';
        resDiv.innerHTML = `
            <div class="alert alert-info shadow-sm">
                <h6 class="fw-bold"><i class="bi bi-shield-check me-2"></i>Resultado para: ${input.value}</h6>
                <p class="mb-0">No se registran denuncias previas con bloqueo judicial activo.</p>
            </div>
        `;
    }
}

function cargarDenunciasPoliciales() {
    const tbody = document.getElementById('tablaPolicial');
    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td>#101</td>
                <td>${new Date().toLocaleDateString('es-AR')}</td>
                <td>División Delitos Tecnológicos</td>
                <td>Estafa WhatsApp</td>
                <td>Alias: cobro.express.mp</td>
                <td>$ 150.000</td>
                <td><span class="badge bg-warning text-dark">En Triage</span></td>
                <td><button class="btn btn-sm btn-primary">Ver Caso</button></td>
            </tr>
        `;
    }
}

function cargarCausasJudiciales() {
    const tbody = document.getElementById('tablaJudicial');
    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td>MPF-PRN-2026-0042</td>
                <td>Jefatura Departamental Paraná</td>
                <td>Phishing Bancario</td>
                <td>22 Números (CBU Verificado)</td>
                <td>$ 850.000</td>
                <td><span class="badge bg-danger">Oficio Emitido</span></td>
            </tr>
        `;
    }
}
