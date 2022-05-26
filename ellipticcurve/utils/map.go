package utils

type Map struct {}

func ReverseMap(m map[string]string) map[string]string {
    n := make(map[string]string, len(m))
    for k, v := range m {
        n[v] = k
    }
    return n
}
