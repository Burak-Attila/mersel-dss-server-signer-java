package io.mersel.dss.signer.api.dtos;

import javax.validation.constraints.NotBlank;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * CAdES imzalama endpoint'ine gönderilen isteğin veri taşıma nesnesi.
 *
 * <p>Multipart/form-data olarak gönderilir. {@code document} alanı imzalanacak
 * dosyayı, {@code detached} alanı imza modunu, {@code level} alanı ise üretilecek
 * CAdES seviyesini belirler.</p>
 *
 * <p>Desteklenen seviye değerleri (büyük/küçük harf ayrımsız, çizgi/altçizgi
 * birbirinin yerine kullanılabilir):</p>
 * <ul>
 *   <li>{@code BES}   — CAdES-BASELINE-B (varsayılan). {@code SigningCertificateV2} attribute barındıran CMS zarfı.</li>
 *   <li>{@code T}     — BES + RFC 3161 imza zaman damgası</li>
 *   <li>{@code X-LONG} / {@code XLONG} / {@code X_LONG} — CAdES-X-Long: CRL/OCSP
 *       verileri imzanın içine gömülür</li>
 *   <li>{@code ESA}   — ETSI Archive Signature (CAdES-A): X-Long + arşiv
 *       zaman damgası</li>
 * </ul>
 *
 * <p>Örnek cURL kullanımı:</p>
 * <pre>{@code
 * curl -X POST http://localhost:8080/v1/cadessign \
 *   -F "document=@fatura.xml" \
 *   -F "detached=true" \
 *   -F "level=X-LONG"
 * }</pre>
 */
public class SignCadesDto {

    /**
     * İmzalanacak dosya. Format kısıtlaması yoktur; CAdES her türlü
     * binary ve text içeriği imzalayabilir.
     */
    private MultipartFile Document;

    /**
     * İmza modu seçimi.
     * {@code true} → detached: yalnızca imza üretilir, orijinal dosya ayrı kalır.
     * {@code false} veya {@code null} → attached: dosya CMS zarfının içine gömülür.
     */
    private Boolean Detached;

    /**
     * Üretilecek CAdES seviyesi. {@code null} veya boş bırakılırsa {@code BES} kullanılır.
     */
    private String Level;

    @Schema(description = "İmzalanacak dosya (zorunlu). Her türlü dosya formatı kabul edilir.",
            required = true)
    public MultipartFile getDocument() {
        return Document;
    }

    @NotBlank
    public void setDocument(MultipartFile document) {
        Document = document;
    }

    @Schema(description = "true ise detached imza (ayrık), false ise attached imza (gömülü). Varsayılan: false",
            example = "false")
    public Boolean getDetached() {
        return Detached;
    }

    public void setDetached(Boolean detached) {
        Detached = detached;
    }

    @Schema(description = "CAdES imza seviyesi: BES, T, X-LONG, ESA. Varsayılan: BES. " +
            "X-LONG ve ESA seviyelerinde CRL/OCSP verisi imzaya gömülür ve TSA yapılandırması zorunludur.",
            example = "BES",
            allowableValues = {"BES", "T", "X-LONG", "ESA"})
    public String getLevel() {
        return Level;
    }

    public void setLevel(String level) {
        Level = level;
    }
}
