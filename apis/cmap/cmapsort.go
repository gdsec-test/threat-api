package main

import (
	"strconv"

	"github.secureserver.net/clake1/cmap-go/cmap"
)

// Sort interface for cmapresults to sort by shopper id

type cmapResultsType []*cmap.DomainQuery

func (c *cmapResultsType) Len() int {
	return len(*c)
}

func (c *cmapResultsType) Less(a, b int) bool {
	shopperIDA, err := strconv.Atoi(string((*c)[a].DomainQuery.ShopperID))
	if err != nil {
		shopperIDA = 0
	}
	shopperIDB, err := strconv.Atoi(string((*c)[b].DomainQuery.ShopperID))
	if err != nil {
		shopperIDB = 0
	}
	return shopperIDA < shopperIDB
}

func (c *cmapResultsType) Swap(a, b int) {
	tmp := (*c)[a]
	(*c)[a] = (*c)[b]
	(*c)[b] = tmp
}
