#import <UIKit/UIKit.h>

/// 激活成功后发出(面板自动淡出前),宿主逻辑据此启动心跳
extern NSString * const AuthUIActivatedNotification;

@interface AuthUI : NSObject

/// 弹出精简激活面板(独立高层级窗口,永远置顶;失败不消失可重试)
+ (void)showOnHostWindow:(UIWindow *)hostWindow;

/// 激活成功后由面板内部调用:延迟淡出并释放面板窗口
+ (void)closePanelAfterDelay:(NSTimeInterval)delay;

@end
