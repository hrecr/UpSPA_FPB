// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Go'da test fonksiyonları her zaman "Test" kelimesiyle başlar ve (t *testing.T) parametresi alır.
func TestHandleHealth(t *testing.T) {
	// 1. ADIM: Sahte bir müşteri isteği (Request) oluşturuyoruz
	// İnternetten geliyormuş gibi "/v1/health" adresine bir GET isteği hazırlıyoruz.
	req, err := http.NewRequest("GET", "/v1/health", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// 2. ADIM: Sahte bir kargo kutusu (Response Recorder) oluşturuyoruz
	// Sunucumuz cevabı internete değil, inceleyebilmemiz için bu sahte kutuya yazacak.
	rr := httptest.NewRecorder()

	// 3. ADIM: Test edeceğimiz fonksiyonu çalıştırıyoruz!
	// Trafik polisine falan gerek yok, doğrudan handleHealth odasına sahte isteği ve kutuyu yolluyoruz.
	handleHealth(rr, req)

	// 4. ADIM: KONTROL 1 - Statü Kodu Doğru mu?
	// 200 OK bekliyoruz. Bakalım gerçekten 200 mü dönmüş?
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Wrong status code returned! Expected: %v, Got: %v", http.StatusOK, status)
	}

	// 5. ADIM: KONTROL 2 - Gelen JSON Metni Doğru mu?
	// Bizim WriteJSON aletimiz sonuna gizli bir alt satıra geçme (\n) karakteri ekleyebilir.
	// O yüzden strings.TrimSpace ile o boşlukları temizleyip asıl metne bakıyoruz.
	expected := `{"ok":true}`
	actual := strings.TrimSpace(rr.Body.String())

	if actual != expected {
		t.Errorf("Wrong response body returned! Expected: %s, Got: %s", expected, actual)
	}
}