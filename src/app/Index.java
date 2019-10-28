package app;

public class Index {
	int i;
	int j;
	Object attribute;

	public Index(int i, int j, Object attribute) {
		this.i = i;
		this.j = j;
		this.attribute = attribute;
	}

	public static Object ContainedIn(Index[] indices, int i, int j) {
		for (Index index : indices) {
			if (index.i == i && index.j == j) {
				return index.attribute;
			}
		}
		return null;
	}
}