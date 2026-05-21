package io.mersel.dss.signer.api.controllers;

import java.util.UUID;

import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.CadesSignatureLevel;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.mersel.dss.signer.api.dtos.SignCadesDto;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;

/**
 * CAdES elektronik imza operasyonlarını yöneten REST controller.
 *
 * <p>CAdES (CMS Advanced Electronic Signatures), ETSI TS 101 733 / EN 319 122-1
 * standartlarına uygun olarak her türlü dosya formatı üzerinde dijital imza
 * oluşturmayı sağlar. Bu controller multipart/form-data üzerinden gelen dosyaları
 * alıp imzalar ve sonucu PKCS#7 (.p7s) formatında döndürür.</p>
 *
 * <p>Desteklenen imza seviyeleri ({@link CadesSignatureLevel}):</p>
 * <ul>
 *   <li><b>BES</b> (varsayılan)</li>
 *   <li><b>T</b> — BES + RFC 3161 zaman damgası</li>
 *   <li><b>X-LONG</b> — CRL/OCSP verileri imza zarfına gömülür</li>
 *   <li><b>ESA</b> — Archive timestamp ile uzun dönem arşiv (CAdES-A)</li>
 * </ul>
 *
 * <p>Desteklenen imza modları:</p>
 * <ul>
 *   <li><b>Attached (gömülü):</b> İmzalanan içerik CMS zarfının içine gömülür.</li>
 *   <li><b>Detached (ayrık):</b> Yalnızca imza verisi üretilir.</li>
 * </ul>
 *
 * <p>Detached modda imza değeri ayrıca {@code x-signature-value} response header'ında
 * Base64 olarak da gönderilir. Attached modda bu header eklenmez çünkü CMS zarfı
 * büyük dosyalarda HTTP header boyut limitini aşabilir.</p>
 *
 * @see CAdESSignatureService
 * @see CadesSignatureLevel
 * @see SigningMaterial
 */
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class CadesController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CadesController.class);

    private final CAdESSignatureService cadesSignatureService;
    private final SigningMaterial signingMaterial;

    public CadesController(CAdESSignatureService cadesSignatureService,
                           SigningMaterial signingMaterial) {
        this.cadesSignatureService = cadesSignatureService;
        this.signingMaterial = signingMaterial;
    }

    @Operation(
            summary = "Dosyaları CAdES imzası ile imzalar (BES / T / X-LONG / ESA)",
            description = "Her türlü dosya için CAdES elektronik imzası oluşturur. " +
                    "Attached (gömülü) veya detached (ayrık) imza ve BES, T, X-LONG, ESA " +
                    "seviyeleri desteklenir. X-LONG ve ESA seviyelerinde CRL/OCSP verileri " +
                    "imza zarfına gömülür."
    )
    @RequestMapping(value = "/v1/cadessign", method = RequestMethod.POST,
            consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @ApiResponses({
            @ApiResponse(responseCode = "200",
                    description = "CAdES imzası başarıyla oluşturuldu",
                    content = @Content(schema = @Schema(type = "string", format = "binary"))),
            @ApiResponse(responseCode = "400",
                    content = @Content(schema = @Schema(implementation = ErrorModel.class))),
            @ApiResponse(responseCode = "500")
    })
    public ResponseEntity<?> signCades(@ModelAttribute SignCadesDto dto) {
        try {
            if (dto.getDocument() == null || dto.getDocument().isEmpty()) {
                LOGGER.warn("Geçersiz istek: belge eksik");
                return ResponseEntity.badRequest()
                        .body(new ErrorModel("INVALID_INPUT", "Belge zorunludur"));
            }

            boolean detached = Boolean.TRUE.equals(dto.getDetached());

            CadesSignatureLevel level;
            try {
                level = CadesSignatureLevel.fromString(dto.getLevel());
            } catch (IllegalArgumentException ex) {
                LOGGER.warn("Geçersiz CAdES seviyesi: {}", dto.getLevel());
                return ResponseEntity.badRequest()
                        .body(new ErrorModel("INVALID_LEVEL", ex.getMessage()));
            }

            SignResponse result;
            try (java.io.InputStream is = dto.getDocument().getInputStream()) {
                result = cadesSignatureService.signData(is, detached, level, signingMaterial);
            }

            LOGGER.info("CAdES imzası başarıyla oluşturuldu (seviye: {}, detached: {})", level, detached);

            // Attached imzada CMS zarfı orijinal belgeyi de içerdiğinden Base64 hali
            // çok büyük olabilir; bu yüzden header yalnızca detached modda eklenir.
            ResponseEntity.BodyBuilder builder = ResponseEntity.ok()
                    .header("Content-Disposition",
                            "attachment; filename=\"signed-" + UUID.randomUUID() + ".p7s\"")
                    .header("x-cades-level", level.name())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM);
            if (detached) {
                builder = builder.header("x-signature-value", result.getSignatureValue());
            }
            return builder.body(result.getSignedDocument());

        } catch (Exception e) {
            LOGGER.error("CAdES imzası oluşturulurken hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }
}
