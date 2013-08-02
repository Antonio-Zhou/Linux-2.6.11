
/*
 * 将页加入管理区的活动链表头部并递增管理区描述符的nr_active字段
 * */
static inline void
add_page_to_active_list(struct zone *zone, struct page *page)
{
	list_add(&page->lru, &zone->active_list);
	zone->nr_active++;
}

/*
 * 将页加入管理区的活动链表头部并递增管理区描述符的nr_inactive字段
 * */
static inline void
add_page_to_inactive_list(struct zone *zone, struct page *page)
{
	list_add(&page->lru, &zone->inactive_list);
	zone->nr_inactive++;
}

/*
 * 从管理区的活动链表中删除页并递减管理区描述符的nr_active字段
 * */
static inline void
del_page_from_active_list(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	zone->nr_active--;
}

/*
 * 从管理区的活动链表中删除页并递减管理区描述符的nr_inactive字段
 * */
static inline void
del_page_from_inactive_list(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	zone->nr_inactive--;
}

/*
 * 检查页的PG_active标志，依据检查结果，将页从活动或非活动链表中删除，递减管理区描述符的nr_active或nr_inactive字段，若有必要，将PG_active清零
 * */
static inline void
del_page_from_lru(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	if (PageActive(page)) {
		ClearPageActive(page);
		zone->nr_active--;
	} else {
		zone->nr_inactive--;
	}
}
