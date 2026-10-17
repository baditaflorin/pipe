package main

import "crypto/rand"

// words is a curated list of short, phonetically-distinct, easy-to-spell
// English words used to build "say-it-out-loud" ids (?words=1) like
// otter-maple-river-stone. 256 words → a 4-word code is 256^4 ≈ 4.3e9
// possibilities, which (paired with the hard 5-minute TTL and the per-IP
// write limit) is enough to keep a fresh id unguessable while staying
// readable over the phone. Length must stay a power of two so the
// rejection-sampling math below has no modulo bias.
var words = []string{
	"acorn", "amber", "anchor", "angel", "apple", "april",
	"arch", "arrow", "atlas", "autumn", "axis", "bacon", "badge", "baker",
	"banjo", "basil", "beach", "beacon", "bean", "bear", "beaver", "bell",
	"berry", "birch", "bird", "bison", "blink", "bloom", "blue", "board",
	"boat", "bolt", "boot", "bread", "brick", "bridge",
	"brook", "brush", "bubble", "buddy", "bunny", "cabin", "cable", "cactus",
	"cake", "camel", "candle", "canoe", "canyon", "cargo", "carol", "cedar",
	"chalk", "charm", "cherry", "chess", "chili", "cider", "cliff", "cloud",
	"clover", "coal", "cobra", "cocoa", "comet", "coral", "cosmos", "cotton",
	"cove", "crane", "cream", "crow", "crystal", "cube", "daisy",
	"dance", "dawn", "deer", "delta", "denim", "diary", "dime", "dolphin",
	"dome", "donut", "dove", "draft", "dragon", "dream", "drift", "drum",
	"dune", "eagle", "early", "earth", "east", "echo", "elder", "elm",
	"ember", "emerald", "ferry", "fable", "falcon", "fawn", "feather",
	"fern", "fig", "finch", "fjord", "flame", "flint", "float", "fox",
	"frost", "garden", "gecko", "ginger", "glade", "glass", "globe", "gold",
	"grape", "grass", "grove", "gull", "hammer", "harbor", "hawk", "hazel",
	"heron", "hill", "honey", "hop", "ivory", "ivy", "jade", "jasper",
	"jelly", "jewel", "jungle", "kayak", "kelp", "kettle", "kite",
	"koala", "lagoon", "lake", "lantern", "lark", "lava", "leaf", "lemon",
	"lily", "lime", "linen", "lion", "lotus", "lunar", "lynx",
	"maple", "marble", "meadow", "melon", "mint", "mist", "moon", "moss",
	"moth", "mouse", "nectar", "needle", "nest", "noble", "north", "nova",
	"oak", "ocean", "olive", "onyx", "opal", "orbit", "otter", "owl",
	"palm", "panda", "pansy", "peach", "pearl", "pebble", "penguin", "pepper",
	"petal", "pine", "plum", "pond", "poppy", "prairie", "puddle", "quartz",
	"quail", "quill", "rabbit", "radish", "rain", "raven", "reef", "river",
	"robin", "rocket", "rose", "ruby", "rust", "sage", "salt", "sand",
	"sapphire", "scout", "seal", "shade", "shell", "shore", "silver", "sky",
	"slate", "sloth", "snail", "snow", "solar", "sparrow", "spice", "spruce",
	"stone", "storm", "stream", "sugar", "summer", "sun", "swan", "tango",
	"teal", "thistle", "tiger", "topaz", "trail", "tulip", "turtle", "umber",
	"valley", "velvet", "vine", "violet", "walnut", "wave", "willow", "zephyr",
}

// randWordCode returns a 4-word hyphen-joined id such as
// "otter-maple-river-stone". len(words) is 256, so each pick uses one
// rejection-sampled byte with no modulo bias.
func randWordCode() string {
	const n = 4
	if len(words) != 256 {
		// Defensive: keep the no-bias contract honest if the list is edited.
		panic("pipe: words list must be exactly 256 entries")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("pipe: crypto/rand unavailable: " + err.Error())
	}
	out := make([]byte, 0, 28)
	for i := 0; i < n; i++ {
		if i > 0 {
			out = append(out, '-')
		}
		out = append(out, words[int(buf[i])]...)
	}
	return string(out)
}
