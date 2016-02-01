package sid
import (
	"testing"
)



func TestUID(t *testing.T) {
	t.Log(NewToken())
}
func BenchmarkNewToken(b *testing.B)  {
	for i := 0; i < b.N; i++ {
		NewToken()
	}
}